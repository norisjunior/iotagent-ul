/*
 * Copyright 2016 Telefonica Investigación y Desarrollo, S.A.U
 *
 * This file is part of iotagent-ul
 *
 * iotagent-ul is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * iotagent-ul is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with iotagent-ul.
 * If not, seehttp://www.gnu.org/licenses/.
 *
 * For those usages not covered by the GNU Affero General Public License
 * please contact with::[iot_support@tid.es]
 */

'use strict';

var iotAgentLib = require('iotagent-node-lib'),
    commonBindings = require('./../commonBindings'),
    utils = require('../iotaUtils'),
    ulParser = require('../ulParser'),
    mqtt = require('mqtt'),
    async = require('async'),
    constants = require('../constants'),
    context = {
        op: 'IOTAUL.MQTT.Binding'
    },
    mqttClient,
    mqttConn,
    config = require('../configService');


function customPadding(str, blockSize, padder, format) {
  str = new Buffer(str,"utf8").toString(format);
  //1 char = 8bytes
  var bitLength = str.length*8;
  var i = bitLength;

  if(bitLength < blockSize) {
    for(i=bitLength;i<blockSize;i+=8) {
      str += padder;
    }
  } else if(bitLength > blockSize) {
    while((str.length*8)%blockSize != 0) {
      str += padder;
    }
  }
  return new Buffer(str, format).toString("utf8");
}


/**
 * Generate the list of global topics to listen to.
 */
function generateTopics(callback) {
    var topics = [];

    config.getLogger().debug(context, 'Generating topics');
    topics.push('/+/+'); //lwpubsub - without attrs (MEASURES_SUFIX)
    topics.push(constants.MQTT_SHARE_SUBSCRIPTION_GROUP + '/+/+/' + constants.MEASURES_SUFIX + '/+');
    topics.push(
        constants.MQTT_SHARE_SUBSCRIPTION_GROUP +
            constants.MQTT_TOPIC_PROTOCOL +
            '/+/+/' +
            constants.MEASURES_SUFIX +
            '/+'
    );
    topics.push(constants.MQTT_SHARE_SUBSCRIPTION_GROUP + '/+/+/' + constants.MEASURES_SUFIX);
    topics.push(
        constants.MQTT_SHARE_SUBSCRIPTION_GROUP + constants.MQTT_TOPIC_PROTOCOL + '/+/+/' + constants.MEASURES_SUFIX
    );
    topics.push(
        constants.MQTT_SHARE_SUBSCRIPTION_GROUP +
            '/+/+/' +
            constants.CONFIGURATION_SUFIX +
            '/' +
            constants.CONFIGURATION_COMMAND_SUFIX
    );
    topics.push(
        constants.MQTT_SHARE_SUBSCRIPTION_GROUP +
            constants.MQTT_TOPIC_PROTOCOL +
            '/+/+/' +
            constants.CONFIGURATION_SUFIX +
            '/' +
            constants.CONFIGURATION_COMMAND_SUFIX
    );
    topics.push(constants.MQTT_SHARE_SUBSCRIPTION_GROUP + '/+/+/' + constants.CONFIGURATION_COMMAND_UPDATE);
    topics.push(
        constants.MQTT_SHARE_SUBSCRIPTION_GROUP +
            constants.MQTT_TOPIC_PROTOCOL +
            '/+/+/' +
            constants.CONFIGURATION_COMMAND_UPDATE
    );

    callback(null, topics);
}

/**
 * Recreate the MQTT subscriptions.
 */
function recreateSubscriptions(callback) {
    config.getLogger().debug(context, 'Recreating global subscriptions');

    function subscribeToTopics(topics, callback) {
        config.getLogger().debug('Subscribing to topics: %j', topics);

        mqttClient.subscribe(topics, null, function(error) {
            if (error) {
                iotAgentLib.alarms.raise(constants.MQTTB_ALARM, error);
                config.getLogger().error(context, ' GLOBAL-001: Error subscribing to topics: %s', error);
                callback(error);
            } else {
                iotAgentLib.alarms.release(constants.MQTTB_ALARM);
                config.getLogger().debug('Successfully subscribed to the following topics:\n%j\n', topics);
                if (callback) {
                    callback(null);
                }
            }
        });
    }

    async.waterfall([generateTopics, subscribeToTopics], callback);
}

/**
 * Unsubscribe the MQTT Client for all the topics of all the devices of all the services.
 */
function unsubscribeAll(callback) {
    function unsubscribeFromTopics(topics, callback) {
        mqttClient.unsubscribe(topics, null);

        callback();
    }

    async.waterfall([generateTopics, unsubscribeFromTopics], callback);
}

/**
 * Generate a function that executes the given command in the device.
 *
 * @param {String} apiKey           APIKey of the device's service or default APIKey.
 * @param {Object} device           Object containing all the information about a device.
 * @param {Object} attribute        Attribute in NGSI format.
 * @return {Function}               Command execution function ready to be called with async.series.
 */
function generateCommandExecution(apiKey, device, attribute) {
    var cmdName = attribute.name,
        cmdAttributes = attribute.value,
        payload;
    var options = {};


        //Noris
        //Teste para ver se dá para pegar o type além da apikey
        // utils.getEffectiveEntityType(device.service, device.subservice, device, function(error, EntityType) {
        //     async.series(attributes.map(generateCommandExecution.bind(null, apiKey, device)), callback);
        // });



    //payload = ulParser.createCommandPayload(device, cmdName, cmdAttributes);
    payload = cmdName + '|' + cmdAttributes;

    /*--------------------------------------------------------------------------------------------------------------*/
    /* Cipher the payload */

    config.getLogger().debug(context, '\n\nCipher the payload! ALGORITHM: ', config.getConfig().lwpubsub.algorithm,
    ' KEY: ', config.getConfig().lwpubsub.aeskey);

    //https://gist.github.com/vlucas/2bd40f62d20c1d49237a109d491974eb
    //https://not.expert/nodejs-crypto-with-custom-padding/
    //https://gist.github.com/silicakes/9080839

    //Cifrar primeiro, montar o payload depois
    const crypto = require('crypto');
    var encryptAlgorithm = config.getConfig().lwpubsub.algorithm;
    var encryptKey = Buffer.from(config.getConfig().lwpubsub.aeskey, 'hex');
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv(encryptAlgorithm, Buffer.from(encryptKey), iv);
    cipher.setAutoPadding(false);


    console.log("\n\nPayload before zero padding text: ", payload, "\n");

    payload = customPadding(payload, 256, 0x0, "hex"); // magic happens here

    console.log("\n\nPayload AFTER zero padding text: ", payload, "\n");


    var encryption = cipher.update(payload);
    encryption = Buffer.concat([encryption, cipher.final()]);
    var encryptedPayload = encryption;


    console.log("Encrypted: ", encryptedPayload);


    //var lwpubsubFirstByte = Buffer.from('30', 'hex');
    //First Byte:
    var lwpubsubFirstByte = Buffer.from('01', 'hex');


    const lwpubsub_aes_nosec = Buffer.from('30', 'hex');
    const lwpubsub_aes_cbc_128 = Buffer.from('01', 'hex');
    const lwpubsub_aes_cbc_192 = Buffer.from('02', 'hex');
    const lwpubsub_aes_cbc_256 = Buffer.from('03', 'hex');
    const lwpubsub_aes_ctr_128 = Buffer.from('11', 'hex');
    const lwpubsub_aes_ctr_192 = Buffer.from('12', 'hex');
    const lwpubsub_aes_ctr_256 = Buffer.from('13', 'hex');



    // Check encryption and construct MQTT payload with: ID (1B) concat with IV (16B) and encrypted message (16B): 33 Bytes
    if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('no-sec')) !== 0)) {
      if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-128-cbc')) == 0)) {
        lwpubsubFirstByte = Buffer.from('01', 'hex');
      } else if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-192-cbc')) == 0)) {
        lwpubsubFirstByte = Buffer.from('02', 'hex');
      } else if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-256-cbc')) == 0)) {
        lwpubsubFirstByte = Buffer.from('03', 'hex');
      } else if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-128-ctr')) == 0)) {
        lwpubsubFirstByte = Buffer.from('11', 'hex');
      } else if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-192-ctr')) == 0)) {
        lwpubsubFirstByte = Buffer.from('12', 'hex');
      } else if ((Buffer.compare(Buffer.from(encryptAlgorithm), Buffer.from('aes-256-ctr')) == 0)) {
        lwpubsubFirstByte = Buffer.from('13', 'hex');
      }
    } else {
      lwpubsubFirstByte = Buffer.from('30', 'hex'); //no sec for testing purposes
    }

    //Construct payload
    //finalPayload = Buffer.concat([lwpubsubFirstByte, iv, payload]);
    var finalPayload = Buffer.concat([lwpubsubFirstByte, iv, encryptedPayload])

    console.log("\n\n\n\nlwpubsubFirstByte", lwpubsubFirstByte, "iv: ", iv, "encr.: ", encryptedPayload);

    console.log("\n\n\nfinalPayload: ", finalPayload);











    if (config.getConfig().mqtt.qos) {
        options.qos = parseInt(config.getConfig().mqtt.qos) || 0;
    }
    if (config.getConfig().mqtt.retain === true) {
        options.retain = config.getConfig().mqtt.retain;
    }
    // prettier-ignore
    config.getLogger().debug(
        context,
        'Sending command execution to device [%s] with apikey [%s] and payload [%s] ',
        apiKey,
        device.id,
        finalPayload
    );
    var commandTopic = '/' + apiKey + '/' + device.id + '/cmd';
    //return mqttClient.publish.bind(mqttClient, commandTopic, payload, options);
    return mqttClient.publish.bind(mqttClient, commandTopic, finalPayload, options);
}

/**
 * Handles a command execution request coming from the Context Broker. This handler should:
 *  - Identify the device affected by the command.
 *  - Send the command to the appropriate MQTT topic.
 *  - Update the command status in the Context Broker.
 *
 * @param {Object} device           Device data stored in the IOTA.
 * @param {String} attributes       Command attributes (in NGSIv1 format).
 */
function commandHandler(device, attributes, callback) {
    config.getLogger().debug(context, 'Handling MQTT command for device [%s]', device.id);

    utils.getEffectiveApiKey(device.service, device.subservice, device, function(error, apiKey) {
        async.series(attributes.map(generateCommandExecution.bind(null, apiKey, device)), callback);
    });
}

/**
 * Extract all the information from a Context Broker response and send it to the topic indicated by the APIKey and
 * DeviceId.
 *
 * @param {String} apiKey           API Key for the Device Group
 * @param {String} deviceId         ID of the Device.
 * @param {Object} results          Context Broker response.
 */
function sendConfigurationToDevice(apiKey, deviceId, results, callback) {
    var configurations = utils.createConfigurationNotification(results);
    var options = {};
    var payload;

    if (config.getConfig().mqtt.qos) {
        options.qos = parseInt(config.getConfig().mqtt.qos) || 0;
    }

    if (config.getConfig().mqtt.retain === true) {
        options.retain = config.getConfig().mqtt.retain;
    }

    payload = ulParser.createConfigurationPayload(deviceId, configurations);
    config
        .getLogger()
        .debug(
            context,
            'Sending requested configuration to device [%s] with apikey [%s] and payload [%s] ',
            deviceId,
            apiKey,
            payload
        );
    var commandTopic =
        '/' +
        apiKey +
        '/' +
        deviceId +
        '/' +
        constants.CONFIGURATION_SUFIX +
        '/' +
        constants.CONFIGURATION_VALUES_SUFIX;
    mqttClient.publish(commandTopic, payload, options, callback);
}

/**
 * Starts the IoT Agent with the passed configuration. This method also starts the listeners for all the transport
 * binding plugins.
 */
function start(callback) {
    if (!config.getConfig().mqtt) {
        return config.getLogger().error(context, 'Error MQTT is not configured');
    }
    var options = {
        keepalive: 0,
        connectTimeout: 60 * 60 * 1000
    };

    if (config.getConfig().mqtt && config.getConfig().mqtt.username && config.getConfig().mqtt.password) {
        options.username = config.getConfig().mqtt.username;
        options.password = config.getConfig().mqtt.password;
    }
    if (config.getConfig().mqtt.keepalive) {
        options.keepalive = parseInt(config.getConfig().mqtt.keepalive) || 0;
    }
    var retries, retryTime;

    if (config.getConfig() && config.getConfig().mqtt && config.getConfig().mqtt.retries) {
        retries = config.getConfig().mqtt.retries;
    } else {
        retries = constants.MQTT_DEFAULT_RETRIES;
    }
    if (config.getConfig() && config.getConfig().mqtt && config.getConfig().mqtt.retrytime) {
        retryTime = config.getConfig().mqtt.retryTime;
    } else {
        retryTime = constants.MQTT_DEFAULT_RETRY_TIME;
    }
    var isConnecting = false;
    var numRetried = 0;
    config.getLogger().info(context, 'Starting MQTT binding');

    function createConnection(callback) {
        config.getLogger().info(context, 'creating connection');
        if (isConnecting) {
            return;
        }
        isConnecting = true;
        mqttClient = mqtt.connect(
            'mqtt://' + config.getConfig().mqtt.host + ':' + config.getConfig().mqtt.port,
            options
        );
        isConnecting = false;
        // TDB: check if error
        if (!mqttClient) {
            config.getLogger().error(context, 'error mqttClient not created');
            if (numRetried <= retries) {
                numRetried++;
                return setTimeout(createConnection, retryTime * 1000, callback);
            }
        }
        mqttClient.on('error', function(e) {
            /*jshint quotmark: double */
            config.getLogger().fatal("GLOBAL-002: Couldn't connect with MQTT broker: %j", e);
            /*jshint quotmark: single */
            if (callback) {
                callback(e);
            }
        });
        mqttClient.on('message', commonBindings.mqttMessageHandler);
        mqttClient.on('connect', function(ack) {
            config.getLogger().info(context, 'MQTT Client connected');
            recreateSubscriptions();
        });
        mqttClient.on('close', function() {
            // If mqttConn is null, the connection has been closed on purpose
            if (mqttConn) {
                if (numRetried <= retries) {
                    config.getLogger().warn(context, 'reconnecting...');
                    numRetried++;
                    return setTimeout(createConnection, retryTime * 1000);
                }
            } else {
                return;
            }
        });

        config.getLogger().info(context, 'connected');
        mqttConn = mqttClient;
        if (callback) {
            callback();
        }
    } // function createConnection

    async.waterfall([createConnection], function(error) {
        if (error) {
            config.getLogger().debug('MQTT error %j', error);
        }
        callback();
    });
}

/**
 * Stops the IoT Agent and all the transport plugins.
 */
function stop(callback) {
    config.getLogger().info('Stopping MQTT Binding');

    async.series([unsubscribeAll, mqttClient.end.bind(mqttClient, true)], function() {
        config.getLogger().info('MQTT Binding Stopped');
        if (mqttConn) {
            mqttConn = null;
        }
        callback();
    });
}

exports.sendConfigurationToDevice = sendConfigurationToDevice;
exports.commandHandler = commandHandler;
exports.start = start;
exports.stop = stop;
exports.protocol = 'MQTT';
