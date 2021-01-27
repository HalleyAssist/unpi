// 'use strict';

const util = require('util'),
      EventEmitter = require('events'),
      Concentrate = require('concentrate'),
      DChunks = require('dissolve-chunks'),
      Q = require('q-lite'),
      assert = require('assert'),
      ru = DChunks.Rule;

const cmdType = {
    "POLL": 0,
    "SREQ": 1,
    "AREQ": 2,
    "SRSP": 3,
    "RES0": 4,
    "RES1": 5,
    "RES2": 6,
    "RES3": 7
};

/*************************************************************************************************/
/*** TI Unified NPI Packet Format                                                              ***/
/***     SOF(1) + Length(2/1) + Type/Sub(1) + Cmd(1) + Payload(N) + FCS(1)                     ***/
/*************************************************************************************************/
function Unpi(config) {
    if (config !== undefined && (typeof config !== 'object' || Array.isArray(config)))
        throw new TypeError('config should be an object if given.');

    EventEmitter.call(this);

    this.config = config || {};
    this.config.lenBytes = this.config.lenBytes || 2;

    const pRules = [
        ru._unpiHeader('sof'),
        ru._unpiLength('len', this.config.lenBytes),
        ru._unpiCmd0('type', 'subsys'),
        ru.uint8('cmd'),
        ru._unpiPayload('payload'),
        ru.uint8('fcs')
    ];

    this.parser = (new DChunks()).join(pRules).compile();
    assert(this.parser)
    const stream = this.parser.stream()
    this._parsed = result => {
        const cmd0 = (result.type << 5) | result.subsys,
              preBuf = Buffer.alloc(this.config.lenBytes + 2);

        if (this.config.lenBytes === 1) {
            preBuf.writeUInt8(result.len, 0);
            preBuf.writeUInt8(cmd0, 1);
            preBuf.writeUInt8(result.cmd, 2);
        } else {
            preBuf.writeUInt16LE(result.len, 0);
            preBuf.writeUInt8(cmd0, 2);
            preBuf.writeUInt8(result.cmd, 3);
        }
        result.csum = checksum(preBuf, result.payload);

        /*const data = Object.assign({}, result)
        data.payload = [...data.payload]
        unpiCapture.push({
            method: 'receive',
            data
        })*/

        this.emit('data', result);
    }
    stream.on('parsed', this._parsed);
    this.stream = stream

    if (this.config.phy) {
        this.config.phy.pipe(stream);
    }
}

const EmptyBuffer = Buffer.alloc(0)

util.inherits(Unpi, EventEmitter);

Unpi.DChunks = DChunks;
Unpi.Concentrate = Concentrate;

/*
let unpiCapture = []
setTimeout(function(){
    const fs = require('fs')
    fs.writeFileSync("/tmp/dump.json", JSON.stringify(unpiCapture))
}, 60000)
*/

Unpi.prototype.send = async function (type, subsys, cmdId, payload) {
    if (typeof type !== 'string' && typeof type !== 'number') 
        throw new TypeError('Argument type should be a string or a number.');
    else if (typeof type === 'number' && isNaN(type))
        throw new TypeError('Argument type cannot be NaN.');

    if (typeof subsys !== 'number')
        throw new TypeError('Argument subsys should be a number.');
    else if (typeof subsys === 'number' && isNaN(subsys))
        throw new TypeError('Argument subsys cannot be NaN.');

    if (typeof cmdId !== 'number' || isNaN(cmdId))
        throw new TypeError('Command id should be a number.');

    if (payload !== undefined && !Buffer.isBuffer(payload))
        throw new TypeError('Payload should be a buffer.');

    type = getCmdTypeString(type);

    if (type === undefined || subsys === undefined)
        throw new Error('Invalid command type or subsystem.');

    /*
    unpiCapture.push({
        method: 'send',
        data: {
            type, subsys, cmdId, payload: [...payload]
        }
    })
    */

    type = cmdType[type];
    payload = payload || Buffer.alloc(0);

    const sof = 0xFE,
          cmd0 = ((type << 5) & 0xE0) | (subsys & 0x1F)

    const preBuf = Buffer.alloc(this.config.lenBytes + 2);

    if (this.config.lenBytes === 1) {
        preBuf.writeUInt8(payload.length, 0);
        preBuf.writeUInt8(cmd0, 1);
        preBuf.writeUInt8(cmdId, 2);
    } else if (this.config.lenBytes === 2) {
        preBuf.writeUInt16LE(payload.length, 0);
        preBuf.writeUInt8(cmd0, 2);
        preBuf.writeUInt8(cmdId, 3);
    }

    const fcs = checksum(preBuf, payload);
    const packet = Concentrate().uint8(sof).buffer(preBuf).buffer(payload).uint8(fcs).result();
    
    let error, eFn
    if(this.config.phy){
        const deferred2 = Q.defer()
        eFn = e=>{
            deferred.reject(e)
            error = e
        }
        this.config.phy.on('error', eFn)
        try {
            const deferred = Q.defer()
            const writeResult = this.config.phy.write(packet, null, err=>{
                if(err) deferred.reject(err)
                deferred.resolve()
            })
            await (deferred.promise.timeout(1150))
            if(!writeResult){
                this.config.phy.drain(err=>{
                    if(err) deferred2.reject(err)
                    deferred2.resolve()
                })
                await (deferred2.promise.timeout(1100))
            }
        } finally {
            this.config.phy.removeListener('error', eFn)
            if(error){
                throw error
            }
        }
    }

    this.emit('flushed', { type , subsys, cmdId });

    return packet;
};

Unpi.prototype.receive = function (buf) {
    if (buf === undefined || buf === null)
        buf = EmptyBuffer;

    if (!Buffer.isBuffer(buf))
        throw new TypeError('buf should be a Buffer.');

    this.stream.write(buf)

    return this;
};

Unpi.prototype.close = function(){
    this.stream.removeListener('parsed', this._parsed);
    this.config.phy.unpipe(this.stream);
}

/*************************************************************************************************/
/*** Parsing Clauses                                                                           ***/
/*************************************************************************************************/
ru.clause('_unpiHeader', function (name) {
    this.loop(function (end) {
        this.uint8(name).tap(function () {
            if (this.vars[name] !== 0xFE)
                delete this.vars[name];
            else
                end();
        });
    });
});

ru.clause('_unpiLength', function (name, bytes) {
    if (bytes === 1)
        this.uint8(name);
    else
        this.uint16(name);
});

ru.clause('_unpiCmd0', function (type, subsys) {
    this.uint8('cmd0').tap(function () {
        this.vars[type] = (this.vars.cmd0 & 0xE0) >> 5;
        this.vars[subsys] = this.vars.cmd0 & 0x1F;
        delete this.vars.cmd0;
    });
});

ru.clause('_unpiPayload', function (name) {
    this.tap(function () {
        this.buffer(name, this.vars.len);
    });
});

function checksum(buf1, buf2) {
    var fcs = 0,
        buf1_len = buf1.length,
        buf2_len = buf2.length,
        i;

    for (i = 0; i < buf1_len; i += 1) {
        fcs ^= buf1[i];
    }

    if (buf2 !== undefined) {
        for (i = 0; i < buf2_len; i += 1) {
            fcs ^= buf2[i];
        }
    }

    return fcs;
}

function getCmdTypeString(cmdtype) {
    var cmdTypeString;

    if (typeof cmdtype === 'number') {
        for (const k in cmdType) {
            if (cmdType.hasOwnProperty(k) && cmdType[k] === cmdtype) {
                cmdTypeString = k;
                break;
            }
        }
    } else if (typeof cmdtype === 'string') {
        if (cmdType.hasOwnProperty(cmdtype))
            cmdTypeString = cmdtype;
    }
    return cmdTypeString;
}

module.exports = Unpi;