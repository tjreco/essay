/**
 * Created by Administrator on 2015/6/2.
 */

//dependencies
var _ = require('lodash');
var promise = require('../../utils/promise');
var State = require('./connectionstate');
var connection = require('./connection');
var iosession = require('./iosession');
var socket = require('./socket');
var keyExchange = require('../crypto/factory').createKeyExchange();
var session = require('./socketsession');
var repeat = require('../../utils/repeat');
var authentication = require('./authentication');
var objects = require('../../utils/objects');
var ConnectionType = require('./connectiontype');
var MessageConstants = require('../../constants/messageconstants');
var SocketRequestResponseTagMap = require('./SocketRequestResponseTagMap');
var AccountStore = require('../../stores/accountstore');
var serverEnv = require('../../datamodel/serverenv');
var predicate = require('../../utils/predicates');

//private const fields
var PUBLIC_KEY_FIELD = "pbk";
var HANDSHAKE_TAG = "HSKN";
var AUTH_TAG = "AUTH";
var PING_TAG = "P";
var SOCKET_HOSTS = [];
var PING_INTERVAL = 25 * 1000;
var SOCKET_IDLE_TIMEOUT = 1 * 60 * 1000;
var DEFAULT_CONFIG = {
    'needEncrypt': true,
    'needDecrypt': true,
    'needCompress': false,
    'needDecompress': false,
    'needEncode': false,
    'needDecode': false,
    'needToken': false,
    'needWrap': false,
    'needUnwrap': true,
    'urlRoot': "",
    'encryptKey': "",
    'encryptKeyForEncryptKey': require('fs').readFileSync(__dirname + '/../crypto/socket_pub_key.pem').toString('utf8'),
    'connectionType': ConnectionType.SOCKET
};

//private fields.
var tokenPromise = null;
var handshakePromise = null;
var authorizePromise = null;
var state = State.INITIALIZING;
var isAuthorized = false;
var autoReconnect = true;
var shouldPing = true;
var reconnectTimes = 0;
var reconnectMaxTimes = 3;
var pingTimer;
var predicatedTaskList = {};
var socketTimeoutErrorCode = 'socketTimeout';

//core module to export
var socketconnection = module.exports = connection.extend({
    /**
     * post the packet to server and then wait for the response.
     * @param packet {Object|String}
     * @returns {Q.Promise}
     */
    request: function (packet) {
        packet = packetFormalize(packet);

        if (!packet.data && HANDSHAKE_TAG !== packet.tag) {
            return authorize().repeat(get(packet.tag));
        }
        return authorize().then(function (value) {
            //avoid duplicate handshake authorization request.
            if (HANDSHAKE_TAG == packet.tag || AUTH_TAG == packet.tag) {
                return value;
            }
            if (packet.data) {
                return post(packet);
            }
        });
    },
    /**
     * monitor the incoming packet data with specified tag pushed by server
     * @param tag {String}
     * @returns {Q.Promise}
     */
    monitor: function (tag) {
        if (!tag) {
            throw new Error('invalid tag');
        }
        return get(String(tag));
    },
    getState: function () {
        return state;
    },
    isAuthorized: function () {
        return isAuthorized;
    },
    close: function () {
        autoReconnect = false;
        console.log('socket ready to close');
        socket.close();
    }
});

//initialize
socketconnection.on('ready', setState(State.CONNECTING)).then(function () {
    autoReconnect = true;
}).done();
socketconnection.on('connect', setState(State.CONNECTED)).then(function () {
    socketconnection.on('message', setState(State.MESSAGING)).then(onMessageReceived).then(setState(State.CONNECTED)).done();

    // todo: D and BM protocols should be moved to protocols/protocolawaresocketconnection.js
    socketconnection.monitor("D").then(onDisconnect).done();
    socketconnection.monitor("BM").then(onBatchMessage).done();
}).done();
socketconnection.on('closed', setState(State.CLOSING)).then(onClosed).then(setState(State.CLOSED)).done();
setState(State.INITIALIZED)();

//private functions
//just listen to data reception with tag.
function get(tag) {
    return socketconnection.on(tag);
}

function post(packet) {
    var tag = packet.tag;
    var data = packet.data;
    var responseTag = packet.responseTag || tag;

    if (state === State.CLOSED || state === State.CLOSING) {
        if (tag !== HANDSHAKE_TAG) return promise.create(new Error('socket closing or closed'));
        setState(State.INITIALIZED)();
    }

    if (state === State.CONNECTED) {
        setState(State.MESSAGING)();
    }

    recordTask(tag);

    console.info('state: ', inspectState());

    if (state === State.INITIALIZED) {
        setSocketConnectionTimeout();
    }

    if (session.has(tag)) {
        return promise.create(session.fetch(tag));
    }

    //process and write data to session and then send via socket.
    session.write(prepareRequestPacket(tag, data), _.assign({}, DEFAULT_CONFIG)).then(socket.send);

    var taskFinishCallback = function (msg) {
        accomplishTask(tag);
        if (!isTasksAllCompleted()) return msg;
        return setState(state === State.CLOSED || state === State.CLOSING ? state : State.CONNECTED)(msg);
    };

    var taskFailedCallback = function (err) {
        throw taskFinishCallback(err);
    };


    return socketPromiseWithResponseTimer(socketconnection.once(predicate(responseTag, data, packet.predicates)))
        .then(taskFinishCallback, taskFailedCallback);
}

function recordTask(tag) {
    if (!_.has(predicatedTaskList, tag)) return _.set(predicatedTaskList, tag, 1);
    return _.set(predicatedTaskList, tag, _.get(predicatedTaskList, tag) + 1);
}

function accomplishTask(tag) {
    if (!_.has(predicatedTaskList, tag)) return predicatedTaskList;
    const tagCount = _.get(predicatedTaskList, tag);
    if (tagCount > 1) return _.set(predicatedTaskList, tag, tagCount - 1);
    delete predicatedTaskList[tag];
    return predicatedTaskList;
}

function isTasksAllCompleted() {
    return _.isEmpty(predicatedTaskList);
}

function setSocketConnectionTimeout(timer) {
    console.group('setSocketConnectionTimeout: ', timer);
    clearTimeout(timer);

    timer = _.delay(function () {
        clearTimeout(timer);
        if (state !== State.CLOSING && state !== State.CLOSED) {
            socketconnection.emit(socketTimeoutErrorCode, new Error(socketTimeoutErrorCode));
            socket.close();
        }
    }, SOCKET_IDLE_TIMEOUT);

    return socketconnection.once(socketTimeoutErrorCode)
        .then(_.bind(setSocketConnectionTimeout, null, timer));
}

function socketPromiseWithResponseTimer(prom, timeout) {
    return promise.create(function (resolve, reject) {
        var timer = _.delay(reject, timeout || MessageConstants.MESSAGE_CONFIRM_TIMEOUT);

        prom.then(function (msg) {
            clearTimeout(timer);
            resolve(msg);
        }, function (err) {
            clearTimeout(timer);
            reject(err);
        });
    });
}

function packetFormalize(packet) {
    var tag;
    var data;

    if (!packet || _.isEmpty(packet)) {
        throw new Error("empty packet to be sent via socket");
    }
    if (_.isPlainObject(packet)) {
        tag = String(packet.tag || _.keys(packet)[0]);
        data = packet.data || _.get(packet, tag);

        if (!tag) {
            throw new Error('invalid tag');
        }

        var result = {
            tag: tag.toUpperCase()
        };
        if (data && !_.isEmpty(data)) {
            result["data"] = data;
        }
        objects.copyPropsExcept(packet, result, ["tag", "data"]);
        return result;
    }

    return {
        tag: String(tag || packet).toUpperCase(),
        data: null
    };
}

function prepareRequestPacket(tag, data) {
    if (isAuthorized) {
        _.assign(
            data,
            AccountStore.getProfile(['msuid', 'ver']),
            {msqid: authentication.nextEncodedSequence()}
        );
    }
    return _.set({}, tag, data);
}

function setState(newState) {
    return function (msg) {
        state = newState;
        //console.info(require('../../utils/strings').template(
        //    '[{time}] state: {state}',
        //    require('../../utils/dates').formatTime(),
        //    inspectState(state)
        //));
        return msg;
    };
}

function inspectState(st) {
    st = _.isUndefined(st) ? state : st;
    return _.reduce(State, function (memo, value, name) {
        return st === value ? name : memo;
    });
}

function onMessageReceived(msg) {
    return session.read(msg, _.assign({}, DEFAULT_CONFIG)).then(function (value) {
        var data = value.data;
        var tag = predicate(value.tag, data);

        socketconnection.emit(socketTimeoutErrorCode);

        //check whether the message is pushed by server or pulled from server.
        if (tag && !_.isEmpty(socketconnection.listeners(tag))) {
            socketconnection.emit(tag, data);
        } else {
            //if the message pushed by server does not have to notify immediately,
            //then cache it into the session for later use.
            if (shouldNotify(tag)) {
                notifyImmediately(tag, data);
            } else {
                session.cache(tag, data);
            }
        }
    });
}

function onClosed() {
    return promise.create(awaitToClose);

    function awaitToClose(resolve, reject) {
        const toClose = _.bind(awaitToClose, null, resolve, reject);
        switch (state) {
            case State.MESSAGING:
                _.delay(toClose, 500);
                break;
            case State.INITIALIZED:
            case State.CONNECTING:
            case State.CONNECTED:
            case State.MESSAGED:
            case State.CLOSING:
                if (isTasksAllCompleted()) {
                    forceClose(resolve, reject);
                } else {
                    releaseSocketEmitter();
                    _.delay(toClose, 500);
                }
                break;
            case State.CLOSED:
                clearSocketStatus();
                resolve('closed');
                break;
            default:
        }
    }

    function clearSocketStatus() {
        authorizePromise = null;
        handshakePromise = null;
        socketconnection.removeAllListeners('message');
        socketconnection.removeAllListeners('HSK');
        socketconnection.removeAllListeners('AUTH');
        socketconnection.removeAllListeners('P');
        socketconnection.removeAllListeners('D');
        _.set(DEFAULT_CONFIG, 'encryptKey', '');
    }

    function releaseSocketEmitter() {
        var taskToBeRemoved = [];

        _.forEach(_.keys(predicatedTaskList), function (task) {
            if (socketconnection.listenerCount(task)) {
                socketconnection.emit(task, new Error('rejected'));
            } else {
                taskToBeRemoved.push(task);
            }
        });

        _.forEach(taskToBeRemoved, function (task) {
            delete predicatedTaskList[task];
        });
    }

    function forceClose(resolve, reject) {
        clearSocketStatus();
        resolve('closed');
        clearTimeout(pingTimer);

        if (autoReconnect) {
            console.log('reconnecting');
            // trigger reconnect and immediately request history messages
            require('../../actions/messageactions').requestHistoryMessages();
        } else {
            console.log('disconnect');
            shouldPing = false;
        }
    }
}

function authorize() {
    if (!authorizePromise) {
        var issueTime;
        authorizePromise = handshake().then(function () {
            if (!AccountStore.getProfile('tk')) {
                throw new Error('no valid token');
            }

            issueTime = new Date().getTime();

            return post({
                tag: AUTH_TAG,
                data: AccountStore.getProfile(['msuid', 'ver', 'tk', 'devuuid', 'dev']),
                responseTag: SocketRequestResponseTagMap.getResponseTag(AUTH_TAG)
            });
        }).then(function (data) {
            var result = parseInt(data.r, 10);

            if (result === 1) {
                return AccountStore.forceLogout();
            }

            if (result === 2) {
                throw new Error('sever-end error');
            }

            if (result === 3) {
                return AccountStore.refreshToken().then(function () {
                    authorizePromise = null;
                    return authorize();
                });
            }

            if (!authentication.validateSequence(_.get(data, 'msqsid'))) {
                throw new Error("sequence invalid with ", _.get(data, 'msqsid'));
            }

            isAuthorized = true;

            var ct = _.get(data, 'ct');
            if (ct) {
                var serverTime = parseInt(ct);
                var milliDelta = serverTime - issueTime;
                serverEnv.setMilliDelta(milliDelta);
            }

            ping();

            return data;
        }, function (err) {
            console.error(err);
            isAuthorized = false;
            authorizePromise = null;
            throw (err instanceof Error ? err : new Error(err));
        });
    }

    return authorizePromise;
}

function handshake() {
    if (!handshakePromise) {
        handshakePromise = post({
            tag: HANDSHAKE_TAG,
            data: _.set(
                AccountStore.getProfile(['ver']),
                PUBLIC_KEY_FIELD,
                keyExchange.getPublicKey({cipherKey: _.get(DEFAULT_CONFIG, 'encryptKeyForEncryptKey')})
            )
        }).then(function (data) {
            _.set(
                DEFAULT_CONFIG,
                'encryptKey',
                keyExchange.getEncryptKey(
                    _.get(data, PUBLIC_KEY_FIELD),
                    {cipherKey: _.get(DEFAULT_CONFIG, 'encryptKeyForEncryptKey')}
                ));
            return data;
        }, function (err) {
            console.error(err);
            throw (err instanceof Error ? err : new Error(err));
        });
    }

    return handshakePromise;
}

function onBatchMessage(data) {
    var protocol = data["p"];
    var children = data["bms"];
    var common = {};

    _.forEach(_.omit(data, ["p", "bms"]), function (value, key) {
        common[key] = value;
    });
    _.forEach(children, function (child) {
        socketconnection.emit(protocol, _.merge(child, common));
    });
}

function onDisconnect(data) {
    var mode = parseInt(data['m'], 10) || 0;
    if (mode === 4) {
        autoReconnect = true;
    } else {
        autoReconnect = false;
        AccountStore.forceLogout();
    }
}

function ping() {
    if (shouldPing) {
        return authorize().then(function () {
            return _sendPingPacket();
        }).then(function () {
            pingTimer = _.delay(ping, PING_INTERVAL);
        });
    }
}

function shouldNotify(tag) {
    return Math.random() < 0.5;
}

function notifyImmediately(tag, data) {
    console.log('notifyImmediately: ', JSON.stringify({
        'tag': tag,
        'data': data
    }));
}

function _sendPingPacket() {
    return post({
        tag: PING_TAG,
        data: _.assign(AccountStore.getProfile(['msuid', 'ver']), {tmstp: Number(new Date())})
    }, {needToken: false});
}
