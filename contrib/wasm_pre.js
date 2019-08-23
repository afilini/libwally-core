const EMSCRIPTEN_PTR_SIZE = 4;
const WALLY_OK = 0;

const get_big_int_class = () => {
    try {
        // newer node versions or browsers, native type
        if ((typeof BigInt) !== 'undefined') {
            return BigInt;
        }
        // probably on a browser with "big-integer" pre-loaded
        if ((typeof bigInt) !== 'undefined') {
            return bigInt;
        }
    } catch (_) {
    } 

    // nodejs, load the module
    return require('big-integer');
};

let wally_ready = false;

function _wrap_ready(fn) {
    return function () {
        if (!wally_ready) {
            throw "WALLY_NOT_READY";
        }

        fn.apply(this, arguments);
    }
}

function _check_ret(ret) {
    switch (ret) {
        case 0: // WALLY_OK
            return 0;
        case -1:
            throw "WALLY_ERROR";
        case -2:
            throw "WALLY_EINVAL";
        case -3:
            throw "WALLY_ENOMEM";

        default:
            throw "WALLY_UNKNOWN_ERROR";
    }
}

function _wrap_no_check_ret(name, argtypes) {
    return function () {
        if (argtypes.length !== arguments.length) {
            console.log(argtypes, arguments);
            throw "MISSING_ARGUMENTS";
        }

        return Module.ccall(name, 'number', argtypes, arguments) === WALLY_OK;
    }
}

function _wrap_check_ret(name, argtypes) {
    return function() {
        if (argtypes.length !== arguments.length) {
            console.log(argtypes, arguments);
            throw "MISSING_ARGUMENTS";
        }

        return _check_ret(Module.ccall(name, 'number', argtypes, arguments));
    }
}

function _memcpy_to_heap(ptr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        Module.setValue(ptr + i, buffer[i], 'i8');
    }
}

function _memcpy_to_buffer(buffer, ptr, size) {
    for (let i = 0; i < size; i++) {
        buffer[i] = Module.getValue(ptr + i, 'i8');
    }
}

function _wrap_resolve_args(name, argtypes, check_ret=true) {
    const args = [];
    const map = [];

    for (let i = 0; i < argtypes.length; i++) {
        switch (argtypes[i][0]) {
            case 'sized_string':
                args.push('string'); // ptr
                args.push('number'); // size

                map.push({ type: 'sized_string' });
                break;

            case 'out_string':
                args.push('number'); // ptr

                map.push({ type: 'out_string' });
                break;

            case 'int_array':
                args.push('number'); // ptr
                args.push('number'); // size

                map.push({ type: 'int_array' });
                break;

            case 'byte_array':
                args.push('number'); // ptr
                args.push('number'); // size

                map.push({ type: 'byte_array' });
                break;

            case 'ptr_val':
                args.push('number'); // ptr

                map.push({ type: 'ptr_val', datatype: argtypes[i][1] });
                break;

            case 'in_bigint':
                args.push('number'); // low
                args.push('number'); // high

                map.push({ type: 'in_bigint' });
                break;

            case 'out_bigint':
                args.push('number'); // low
                args.push('number'); // high

                map.push({ type: 'out_bigint' });
                break;

            case 'in_buffer':
                args.push('number'); // ptr
                args.push('number'); // size

                map.push({ type: 'in_buffer' });
                break;

            case 'out_buffer':
                args.push('number'); // ptr
                args.push('number'); // size

                const size = argtypes[i][1];
                const resize = argtypes[i].length > 2 ? argtypes[i][2] : false;
                if (resize) {
                    args.push('number'); // written ptr
                }

                map.push({ type: 'out_buffer', size, resize });
                break;

            case 'in_struct':
                args.push('number'); // ptr

                map.push({ type: 'in_struct', struct: argtypes[i][1] });
                break;

            case 'out_struct':
                args.push('number'); // ptr

                map.push({ type: 'out_struct', struct: argtypes[i][1] });
                break;

            default:
                args.push(argtypes[i][0]);

                map.push({ type: 'copy' });
        }
    }

    return function() {
        const mapped_args = [];
        const to_free = [];
        const out_bufs = [];
        const out_strings = [];
        const out_ptr_vals = [];
        const out_structs = [];

        for (let i = 0; i < map.length; i++) {
            switch (map[i].type) {
                case 'copy':
                    mapped_args.push(arguments[i]);
                    break;

                case 'sized_string':
                    if (arguments[i] === null) {
                        mapped_args.push(0);
                        mapped_args.push(0);
                        break;
                    }

                    mapped_args.push(arguments[i]);
                    mapped_args.push(arguments[i].length);
                    break;

                case 'int_array':
                    // TODO: check the type
                    const array_ptr = Module._malloc(4 * arguments[i].length);
                    to_free.push(array_ptr);
                    for (let z = 0; z < arguments[i].length; z++) {
                        Module.setValue(array_ptr + z * 4, arguments[i][z], 'i32');
                    }

                    mapped_args.push(array_ptr);
                    mapped_args.push(arguments[i].length);
                    break;

                case 'byte_array':
                    // TODO: check the type

                    if (arguments[i] === null) {
                        mapped_args.push(0);
                        mapped_args.push(0);
                        break;
                    }

                    const total_len = arguments[i].reduce((a, v) => a + v.length, 0);

                    const byte_arr_ptr = Module._malloc(total_len);
                    to_free.push(byte_arr_ptr);

                    let offset = 0;
                    for (const b of arguments[i]) {
                        _memcpy_to_heap(byte_arr_ptr + offset, b);
                        offset += b.length;
                    }

                    mapped_args.push(byte_arr_ptr);
                    mapped_args.push(total_len);
                    break;

                case 'out_string':
                    const out_str_ptr = Module._malloc(EMSCRIPTEN_PTR_SIZE);
                    mapped_args.push(out_str_ptr);
                    to_free.push(out_str_ptr);

                    out_strings.push(out_str_ptr);
                    break;

                case 'ptr_val':
                    const val_ptr = Module._malloc(EMSCRIPTEN_PTR_SIZE);
                    mapped_args.push(val_ptr);
                    to_free.push(val_ptr);

                    out_ptr_vals.push({ptr: val_ptr, type: map[i].datatype});
                    break;

                case 'in_bigint':
                    // TODO: check the type

                    mapped_args.push(Number(get_big_int_class()(arguments[i]) & get_big_int_class()(0xffffffff)));
                    mapped_args.push(Number(get_big_int_class()(arguments[i]) >> get_big_int_class()(0xffffffff)));
                    break;

                case 'out_bigint':
                    throw "implement out_bigint";
                    break;

                case 'in_buffer':
                    // TODO: check the type

                    if (arguments[i] === null) {
                        mapped_args.push(0);
                        mapped_args.push(0);
                        break;
                    }

                    const heap_ptr = Module._malloc(arguments[i].length);
                    to_free.push(heap_ptr);
                    _memcpy_to_heap(heap_ptr, arguments[i]);

                    mapped_args.push(heap_ptr);
                    mapped_args.push(arguments[i].length);
                    break;

                case 'out_buffer':
                    const resolved_size = typeof map[i].size === 'function' ? map[i].size.apply(this, arguments) : map[i].size;

                    const heap_ptr2 = Module._malloc(resolved_size);
                    to_free.push(heap_ptr2);

                    mapped_args.push(heap_ptr2);
                    mapped_args.push(resolved_size);

                    let resize_ptr = 0;
                    if (map[i].resize) {
                        resize_ptr = Module._malloc(EMSCRIPTEN_PTR_SIZE);
                        mapped_args.push(resize_ptr);
                        to_free.push(resize_ptr);
                    }

                    out_bufs.push({ptr: heap_ptr2, size: resolved_size, resize_ptr});

                    break;

                case 'in_struct':
                    // TODO: validate the type

                    if (arguments[i] === null) {
                        mapped_args.push(0);
                        break;
                    }

                    mapped_args.push(arguments[i]._ptr);
                    break;

                case 'out_struct':
                    const struct_ptr = Module._malloc(EMSCRIPTEN_PTR_SIZE);
                    mapped_args.push(struct_ptr);
                    to_free.push(struct_ptr);

                    out_structs.push({ptr: struct_ptr, struct: map[i].struct});


                    break;

                default:
                    throw "WALLY_INVALID_MAP_WRAP_TYPE";
            }
        }

        const wrapper = check_ret ? _wrap_check_ret : _wrap_no_check_ret;
        const ret = wrapper(name, args).apply(this, mapped_args);

        const native_returns = [];

        // copy out buffers
        for (const buf of out_bufs) {
            const copy_size = buf.resize_ptr == 0 ? buf.size : Module.getValue(buf.resize_ptr, 'i32');

            let native_buf = null;
            if (typeof Buffer !== 'undefined') {
                native_buf = Buffer.alloc(copy_size);
            } else if (typeof Uint8Array !== 'undefined') {
                native_buf = new Uint8Array(copy_size);   
            } else {
                throw "MISSING_BUFFER_POLYFILL";
            }
            native_returns.push(native_buf);

            _memcpy_to_buffer(native_buf, buf.ptr, copy_size);
        }

        // copy strings
        for (const str_ptr of out_strings) {
            const deref_ptr = Module.getValue(str_ptr, '*');
            native_returns.push(Module.UTF8ToString(deref_ptr));
            Module.ccall('wally_free_string', ['number'], [deref_ptr]);
        }

        // copy native values
        for (const val_ptr of out_ptr_vals) {
            // fetch this in two halves
            if (val_ptr.type == 'i64') {
                let v = get_big_int_class()(0);
                v |= get_big_int_class()(Module.getValue(val_ptr.ptr, 'i32'));
                v |= get_big_int_class()(Module.getValue(val_ptr.ptr + 4, 'i32')) << get_big_int_class()(32);
                native_returns.push(v);
            } else {
                native_returns.push(Module.getValue(val_ptr.ptr, val_ptr.type));
            }
        }

        // copy structs
        for (const s of out_structs) {
            native_returns.push(new s.struct(Module.getValue(s.ptr, '*')));
        }

        // free the ptrs
        for (const ptr of to_free) {
            Module._free(ptr);
        }

        if (native_returns.length === 0) {
            return ret;
        } else if (native_returns.length === 1) {
            return native_returns[0];
        }

        return native_returns;
    }
}

// generic wrapped struct
class _wrapped_struct {
    constructor(typename, dtor, ptr) {
        this._typename = typename;
        this._ptr = ptr;

        this._dtor = Module.cwrap(dtor, 'number', ['number']);
    }

    destroy() {
        if (this._dtor === null) {
            return 0;
        }

        const ret = this._dtor(this._ptr);
        this._ptr = 0;

        return ret;
    }

    toString() {
        return `<wrapped object "struct ${this._typename} *" at 0x${this._ptr.toString(16)}>`;
    }

    inspect() {
        return this.toString();
    }
}

Module.BASE58_FLAG_CHECKSUM = 0x1;
Module.BASE58_CHECKSUM_LEN = 4;

Module.SHA256_LEN = 32;
Module.SHA512_LEN = 64;
Module.HASH160_LEN = 20;

Module.AES_BLOCK_LEN = 16;
Module.AES_KEY_LEN_128 = 16;
Module.AES_KEY_LEN_192 = 24;
Module.AES_KEY_LEN_256 = 32;

Module.AES_FLAG_ENCRYPT = 1;
Module.AES_FLAG_DECRYPT = 2;

Module.EC_PRIVATE_KEY_LEN = 32;
Module.EC_PUBLIC_KEY_LEN = 33;
Module.EC_PUBLIC_KEY_UNCOMPRESSED_LEN = 65;
Module.EC_MESSAGE_HASH_LEN = 32;
Module.EC_SIGNATURE_LEN = 64;
Module.EC_SIGNATURE_RECOVERABLE_LEN = 65;
Module.EC_SIGNATURE_DER_MAX_LEN = 72;
Module.EC_SIGNATURE_DER_MAX_LOW_R_LEN = 71;

Module.EC_FLAG_ECDSA = 0x1;
Module.EC_FLAG_SCHNORR = 0x2;
Module.EC_FLAG_GRIND_R = 0x4;
Module.EC_FLAG_RECOVERABLE = 0x8;

Module.BITCOIN_MESSAGE_MAX_LEN = (64 * 1024 - 64);
Module.BITCOIN_MESSAGE_FLAG_HASH = 1;

Module.WALLY_WIF_FLAG_COMPRESSED = 0x0;
Module.WALLY_WIF_FLAG_UNCOMPRESSED = 0x1;

Module.BIP32_ENTROPY_LEN_128 = 16;
Module.BIP32_ENTROPY_LEN_256 = 32;
Module.BIP32_ENTROPY_LEN_512 = 64;

Module.BIP32_SERIALIZED_LEN = 78;

Module.BIP32_INITIAL_HARDENED_CHILD = 0x80000000;

Module.BIP32_FLAG_KEY_PRIVATE = 0x0;
Module.BIP32_FLAG_KEY_PUBLIC =  0x1;
Module.BIP32_FLAG_SKIP_HASH = 0x2;

Module.BIP32_VER_MAIN_PUBLIC =  0x0488B21E;
Module.BIP32_VER_MAIN_PRIVATE = 0x0488ADE4;
Module.BIP32_VER_TEST_PUBLIC =  0x043587CF;
Module.BIP32_VER_TEST_PRIVATE = 0x04358394;

Module.BIP39_ENTROPY_LEN_128 = 16;
Module.BIP39_ENTROPY_LEN_160 = 20;
Module.BIP39_ENTROPY_LEN_192 = 24;
Module.BIP39_ENTROPY_LEN_224 = 28;
Module.BIP39_ENTROPY_LEN_256 = 32;
Module.BIP39_ENTROPY_LEN_288 = 36;
Module.BIP39_ENTROPY_LEN_320 = 40;

Module.BIP39_ENTROPY_LEN_MAX = (Module.BIP39_ENTROPY_LEN_320 + 2);

Module.BIP39_SEED_LEN_512 = 64;
Module.BIP39_WORDLIST_LEN = 2048;

Module.WALLY_SCRIPT_TYPE_UNKNOWN = 0x0;
Module.WALLY_SCRIPT_TYPE_OP_RETURN = 0x1;
Module.WALLY_SCRIPT_TYPE_P2PKH = 0x2;
Module.WALLY_SCRIPT_TYPE_P2SH = 0x4;
Module.WALLY_SCRIPT_TYPE_P2WPKH = 0x8;
Module.WALLY_SCRIPT_TYPE_P2WSH = 0x10;
Module.WALLY_SCRIPT_TYPE_MULTISIG = 0x20;


Module.WALLY_SCRIPTPUBKEY_P2PKH_LEN = 25;
Module.WALLY_SCRIPTPUBKEY_P2SH_LEN = 23;
Module.WALLY_SCRIPTPUBKEY_P2WPKH_LEN = 22;
Module.WALLY_SCRIPTPUBKEY_P2WSH_LEN = 34;

Module.WALLY_SCRIPTPUBKEY_OP_RETURN_MAX_LEN = 83;

Module.WALLY_MAX_OP_RETURN_LEN = 80;

Module.WALLY_SCRIPTSIG_P2PKH_MAX_LEN = 140;
Module.WALLY_WITNESSSCRIPT_MAX_LEN = 35;


Module.WALLY_SCRIPT_HASH160 = 0x1;
Module.WALLY_SCRIPT_SHA256 = 0x2;
Module.WALLY_SCRIPT_AS_PUSH = 0x4;


Module.OP_0 = 0x00;
Module.OP_FALSE = 0x00;
Module.OP_PUSHDATA1 = 0x4c;
Module.OP_PUSHDATA2 = 0x4d;
Module.OP_PUSHDATA4 = 0x4e;
Module.OP_1NEGATE = 0x4f;
Module.OP_RESERVED = 0x50;
Module.OP_1 = 0x51;
Module.OP_TRUE = 0x51;
Module.OP_2 = 0x52;
Module.OP_3 = 0x53;
Module.OP_4 = 0x54;
Module.OP_5 = 0x55;
Module.OP_6 = 0x56;
Module.OP_7 = 0x57;
Module.OP_8 = 0x58;
Module.OP_9 = 0x59;
Module.OP_10 = 0x5a;
Module.OP_11 = 0x5b;
Module.OP_12 = 0x5c;
Module.OP_13 = 0x5d;
Module.OP_14 = 0x5e;
Module.OP_15 = 0x5f;
Module.OP_16 = 0x60;

Module.OP_NOP = 0x61;
Module.OP_VER = 0x62;
Module.OP_IF = 0x63;
Module.OP_NOTIF = 0x64;
Module.OP_VERIF = 0x65;
Module.OP_VERNOTIF = 0x66;
Module.OP_ELSE = 0x67;
Module.OP_ENDIF = 0x68;
Module.OP_VERIFY = 0x69;
Module.OP_RETURN = 0x6a;

Module.OP_TOALTSTACK = 0x6b;
Module.OP_FROMALTSTACK = 0x6c;
Module.OP_2DROP = 0x6d;
Module.OP_2DUP = 0x6e;
Module.OP_3DUP = 0x6f;
Module.OP_2OVER = 0x70;
Module.OP_2ROT = 0x71;
Module.OP_2SWAP = 0x72;
Module.OP_IFDUP = 0x73;
Module.OP_DEPTH = 0x74;
Module.OP_DROP = 0x75;
Module.OP_DUP = 0x76;
Module.OP_NIP = 0x77;
Module.OP_OVER = 0x78;
Module.OP_PICK = 0x79;
Module.OP_ROLL = 0x7a;
Module.OP_ROT = 0x7b;
Module.OP_SWAP = 0x7c;
Module.OP_TUCK = 0x7d;

Module.OP_CAT = 0x7e;
Module.OP_SUBSTR = 0x7f;
Module.OP_LEFT = 0x80;
Module.OP_RIGHT = 0x81;
Module.OP_SIZE = 0x82;

Module.OP_INVERT = 0x83;
Module.OP_AND = 0x84;
Module.OP_OR = 0x85;
Module.OP_XOR = 0x86;
Module.OP_EQUAL = 0x87;
Module.OP_EQUALVERIFY = 0x88;
Module.OP_RESERVED1 = 0x89;
Module.OP_RESERVED2 = 0x8a;

Module.OP_1ADD = 0x8b;
Module.OP_1SUB = 0x8c;
Module.OP_2MUL = 0x8d;
Module.OP_2DIV = 0x8e;
Module.OP_NEGATE = 0x8f;
Module.OP_ABS = 0x90;
Module.OP_NOT = 0x91;
Module.OP_0NOTEQUAL = 0x92;

Module.OP_ADD = 0x93;
Module.OP_SUB = 0x94;
Module.OP_MUL = 0x95;
Module.OP_DIV = 0x96;
Module.OP_MOD = 0x97;
Module.OP_LSHIFT = 0x98;
Module.OP_RSHIFT = 0x99;

Module.OP_BOOLAND = 0x9a;
Module.OP_BOOLOR = 0x9b;
Module.OP_NUMEQUAL = 0x9c;
Module.OP_NUMEQUALVERIFY = 0x9d;
Module.OP_NUMNOTEQUAL = 0x9e;
Module.OP_LESSTHAN = 0x9f;
Module.OP_GREATERTHAN = 0xa0;
Module.OP_LESSTHANOREQUAL = 0xa1;
Module.OP_GREATERTHANOREQUAL = 0xa2;
Module.OP_MIN = 0xa3;
Module.OP_MAX = 0xa4;

Module.OP_WITHIN = 0xa5;

Module.OP_RIPEMD160 = 0xa6;
Module.OP_SHA1 = 0xa7;
Module.OP_SHA256 = 0xa8;
Module.OP_HASH160 = 0xa9;
Module.OP_HASH256 = 0xaa;
Module.OP_CODESEPARATOR = 0xab;
Module.OP_CHECKSIG = 0xac;
Module.OP_CHECKSIGVERIFY = 0xad;
Module.OP_CHECKMULTISIG = 0xae;
Module.OP_CHECKMULTISIGVERIFY = 0xaf;

Module.OP_NOP1 = 0xb0;
Module.OP_CHECKLOCKTIMEVERIFY = 0xb1;
Module.OP_NOP2 = 0xb1;
Module.OP_CHECKSEQUENCEVERIFY = 0xb2;
Module.OP_NOP3 = 0xb2;
Module.OP_NOP4 = 0xb3;
Module.OP_NOP5 = 0xb4;
Module.OP_NOP6 = 0xb5;
Module.OP_NOP7 = 0xb6;
Module.OP_NOP8 = 0xb7;
Module.OP_NOP9 = 0xb8;
Module.OP_NOP10 = 0xb9;

Module.OP_INVALIDOPCODE = 0xff;

Module.WALLY_TX_SEQUENCE_FINAL = 0xffffffff;
Module.WALLY_TX_VERSION_1 = 1;
Module.WALLY_TX_VERSION_2 = 2;
Module.WALLY_TX_IS_ELEMENTS = 1;
Module.WALLY_TX_IS_ISSUANCE = 2;
Module.WALLY_TX_IS_PEGIN = 4;
Module.WALLY_TX_IS_COINBASE = 8;

Module.WALLY_SATOSHI_PER_BTC = 100000000;
Module.WALLY_BTC_MAX = 21000000;

Module.WALLY_TXHASH_LEN = 32;

Module.WALLY_TX_FLAG_USE_WITNESS =  0x1;
Module.WALLY_TX_FLAG_USE_ELEMENTS = 0x2;

Module.WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE = 0x1;

Module.WALLY_TX_DUMMY_NULL = 0x1;
Module.WALLY_TX_DUMMY_SIG =  0x2;
Module.WALLY_TX_DUMMY_SIG_LOW_R =  0x4;


Module.WALLY_SIGHASH_ALL =          0x01;
Module.WALLY_SIGHASH_NONE =         0x02;
Module.WALLY_SIGHASH_SINGLE =       0x03;
Module.WALLY_SIGHASH_FORKID =       0x40;
Module.WALLY_SIGHASH_ANYONECANPAY = 0x80;

Module.WALLY_TX_ASSET_CT_VALUE_PREFIX_A = 8;
Module.WALLY_TX_ASSET_CT_VALUE_PREFIX_B = 9;
Module.WALLY_TX_ASSET_CT_ASSET_PREFIX_A = 10;
Module.WALLY_TX_ASSET_CT_ASSET_PREFIX_B = 11;
Module.WALLY_TX_ASSET_CT_NONCE_PREFIX_A = 2;
Module.WALLY_TX_ASSET_CT_NONCE_PREFIX_B = 3;

Module.WALLY_TX_ASSET_TAG_LEN = 32;
Module.WALLY_TX_ASSET_CT_VALUE_LEN = 33;
Module.WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN = 9;
Module.WALLY_TX_ASSET_CT_ASSET_LEN = 33;
Module.WALLY_TX_ASSET_CT_NONCE_LEN = 33;
Module.WALLY_TX_ASSET_CT_LEN = 33;

Module.WALLY_TX_ISSUANCE_FLAG = (1 << 31);
Module.WALLY_TX_PEGIN_FLAG = (1 << 30);
Module.WALLY_TX_INDEX_MASK = 0x3fffffff;



Module.WALLY_CA_PREFIX_LIQUID = 0x0c;
Module.WALLY_CA_PREFIX_LIQUID_REGTEST = 0x04;

Module.ASSET_TAG_LEN = 32;
Module.ASSET_GENERATOR_LEN = 33;
Module.ASSET_COMMITMENT_LEN = 33;
Module.ASSET_RANGEPROOF_MAX_LEN = 5134;

const wally_init = _wrap_check_ret('wally_init', [['number']]);

Module.hex_from_bytes = _wrap_resolve_args('wally_hex_from_bytes', [['in_buffer'], ['out_string']]);
Module.hex_to_bytes = _wrap_resolve_args('wally_hex_to_bytes', [['string'], ['out_buffer', (s) => (s.length / 2), true]]);
Module.base58_from_bytes = _wrap_resolve_args('wally_base58_from_bytes', [['in_buffer'], ['number'], ['out_string']]);
Module.base58_to_bytes = _wrap_resolve_args('wally_base58_to_bytes', [['string'], ['number'], ['out_buffer', (s) => s.length, true]]);
Module.base58_get_length = _wrap_resolve_args('wally_base58_get_length', [['string'], ['ptr_val', 'i32']]);
Module.is_elements_build = _wrap_resolve_args('wally_is_elements_build', [['ptr_val', 'i64']]);

// wally_crypto
Module.scrypt = _wrap_resolve_args('wally_scrypt', [['in_buffer'], ['in_buffer'], ['number'], ['number'], ['number'], ['out_buffer', 64]]); // TODO: is 64 correct?

Module.aes = _wrap_resolve_args('wally_aes', [['in_buffer'], ['in_buffer'], ['number'], ['out_buffer', (_, data) => data.length]]);
Module.aes_cbc = _wrap_resolve_args('wally_aes_cbc', [['in_buffer'], ['in_buffer'], ['in_buffer'], ['number'], ['out_buffer', (_a, _b, data) => (Math.ceil(data.length / Module.AES_BLOCK_LEN) * Module.AES_BLOCK_LEN + 64), true]]); // TODO: check the length

Module.sha256 = _wrap_resolve_args('wally_sha256', [['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.sha256_midstate = _wrap_resolve_args('wally_sha256_midstate', [['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.sha256d = _wrap_resolve_args('wally_sha256d', [['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.sha512 = _wrap_resolve_args('wally_sha512', [['in_buffer'], ['out_buffer', Module.SHA512_LEN]]);
Module.hash160 = _wrap_resolve_args('wally_hash160', [['in_buffer'], ['out_buffer', Module.HASH160_LEN]]);

Module.hmac_sha256 = _wrap_resolve_args('wally_hmac_sha256', [['in_buffer'], ['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.hmac_sha512 = _wrap_resolve_args('wally_hmac_sha512', [['in_buffer'], ['in_buffer'], ['out_buffer', Module.SHA512_LEN]]);

Module.pbkdf2_hmac_sha256 = _wrap_resolve_args('wally_pbkdf2_hmac_sha256', [['in_buffer'], ['in_buffer'], ['number'], ['number'], ['out_buffer', Module.SHA256_LEN]]);
Module.pbkdf2_hmac_sha512 = _wrap_resolve_args('wally_pbkdf2_hmac_sha512', [['in_buffer'], ['in_buffer'], ['number'], ['number'], ['out_buffer', Module.SHA512_LEN]]);

Module.ec_private_key_verify = _wrap_resolve_args('wally_ec_private_key_verify', [['in_buffer']], false);
Module.ec_public_key_verify = _wrap_resolve_args('wally_ec_public_key_verify', [['in_buffer']], false);
Module.ec_public_key_from_private_key = _wrap_resolve_args('wally_ec_public_key_from_private_key', [['in_buffer'], ['out_buffer', Module.EC_PUBLIC_KEY_LEN]]);
Module.ec_public_key_decompress = _wrap_resolve_args('wally_ec_public_key_decompress', [['in_buffer'], ['out_buffer', Module.EC_PUBLIC_KEY_UNCOMPRESSED_LEN]]);
Module.ec_sig_from_bytes = _wrap_resolve_args('wally_ec_sig_from_bytes', [['in_buffer'], ['in_buffer'], ['number'], ['out_buffer', Module.EC_SIGNATURE_LEN]]);
Module.ec_sig_normalize = _wrap_resolve_args('wally_ec_sig_normalize', [['in_buffer'], ['out_buffer', Module.EC_SIGNATURE_LEN]]);
Module.ec_sig_to_der = _wrap_resolve_args('wally_ec_sig_to_der', [['in_buffer'], ['out_buffer', Module.EC_SIGNATURE_DER_MAX_LEN, true]]);
Module.ec_sig_from_der = _wrap_resolve_args('wally_ec_sig_from_der', [['in_buffer'], ['out_buffer', Module.EC_SIGNATURE_LEN]]);
Module.ec_sig_verify = _wrap_resolve_args('wally_ec_sig_verify', [['in_buffer'], ['in_buffer'], ['number'], ['in_buffer']], false);

const _wally_format_bitcoin_message_len = (msg, flags) => {
    if (flags & Module.BITCOIN_MESSAGE_FLAG_HASH) {
        return Module.SHA256_LEN;
    }

    return 25 + msg.length + (msg.length < 253 ? 1 : 3);
};
Module.format_bitcoin_message = _wrap_resolve_args('wally_format_bitcoin_message', [['sized_string'], ['number'], ['out_buffer', _wally_format_bitcoin_message_len, true]]);

Module.ecdh = _wrap_resolve_args('wally_ecdh', [['in_buffer'], ['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);

// wally_address
Module.addr_segwit_from_bytes = _wrap_resolve_args('wally_addr_segwit_from_bytes', [['in_buffer'], ['string'], ['number'], ['out_string']]);
Module.addr_segwit_to_bytes = _wrap_resolve_args('wally_addr_segwit_to_bytes', [['string'], ['string'], ['number'], ['out_buffer', Module.SHA256_LEN + 2, true]]);
Module.wif_from_bytes = _wrap_resolve_args('wally_wif_from_bytes', [['in_buffer'], ['number'], ['number'], ['out_string']]);
Module.wif_to_bytes = _wrap_resolve_args('wally_wif_to_bytes', [['string'], ['number'], ['number'], ['out_buffer', Module.EC_PRIVATE_KEY_LEN]]);
Module.wif_is_uncompressed = _wrap_resolve_args('wally_wif_is_uncompressed', [['string'], ['ptr_val', 'i32']]);
Module.wif_to_public_key = _wrap_resolve_args('wally_wif_to_public_key', [['string'], ['number'], ['out_buffer', Module.EC_PUBLIC_KEY_UNCOMPRESSED_LEN, true]]);
Module.wif_to_address = _wrap_resolve_args('wally_wif_to_address', [['string'], ['number'], ['number'], ['out_string']]);
// TODO: if is_elements
Module.confidential_addr_to_addr = _wrap_resolve_args('wally_confidential_addr_to_addr', [['string'], ['number'], ['out_string']]);
Module.confidential_addr_to_ec_public_key = _wrap_resolve_args('wally_confidential_addr_to_ec_public_key', [['string'], ['number'], ['out_buffer', Module.EC_PUBLIC_KEY_LEN]]);
Module.confidential_addr_from_addr = _wrap_resolve_args('wally_confidential_addr_from_addr', [['string'], ['number'], ['in_buffer'], ['out_string']]);
// TODO: endif

// wally_bip32
class wally_ext_key extends _wrapped_struct {
    constructor(ptr) {
        super('ext_key', 'bip32_key_free', ptr);
    }
}
Module.bip32_key_init = _wrap_resolve_args('bip32_key_init_alloc', [['number'], ['number'], ['number'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['out_struct', wally_ext_key]]);
Module.bip32_key_from_seed = _wrap_resolve_args('bip32_key_from_seed_alloc', [['in_buffer'], ['number'], ['number'], ['out_struct', wally_ext_key]]);
Module.bip32_key_serialize = _wrap_resolve_args('bip32_key_serialize', [['in_struct', wally_ext_key], ['number'], ['out_buffer', Module.BIP32_SERIALIZED_LEN]]);
Module.bip32_key_unserialize = _wrap_resolve_args('bip32_key_unserialize_alloc', [['in_buffer'], ['out_struct', wally_ext_key]]);
Module.bip32_key_from_parent = _wrap_resolve_args('bip32_key_from_parent_alloc', [['in_struct', wally_ext_key], ['number'], ['number'], ['out_struct', wally_ext_key]]);
Module.bip32_key_from_parent_path = _wrap_resolve_args('bip32_key_from_parent_path_alloc', [['in_struct', wally_ext_key], ['int_array'], ['number'], ['out_struct', wally_ext_key]]);
Module.bip32_key_to_base58 = _wrap_resolve_args('bip32_key_to_base58', [['in_struct', wally_ext_key], ['number'], ['out_string']]);
Module.bip32_key_from_base58 = _wrap_resolve_args('bip32_key_from_base58_alloc', [['string'], ['out_struct', wally_ext_key]]);

// TODO: wally_bip38

// wally_bip39
class wally_words extends _wrapped_struct {
    constructor(ptr) {
        super('words', null, ptr);
    }
}
Module.bip39_get_languages = _wrap_resolve_args('bip39_get_languages', [['out_string']]);
Module.bip39_get_wordlist = _wrap_resolve_args('bip39_get_wordlist', [['string'], ['out_struct', wally_words]]);
Module.bip39_get_word = _wrap_resolve_args('bip39_get_word', [['in_struct', wally_words], ['number'], ['out_string']]);
Module.bip39_mnemonic_from_bytes = _wrap_resolve_args('bip39_mnemonic_from_bytes', [['in_struct', wally_words], ['in_buffer'], ['out_string']]);
Module.bip39_mnemonic_to_bytes = _wrap_resolve_args('bip39_mnemonic_to_bytes', [['in_struct', wally_words], ['string'], ['out_buffer', Module.BIP39_ENTROPY_LEN_MAX, true]]);
Module.bip39_mnemonic_validate = _wrap_resolve_args('bip39_mnemonic_validate', [['in_struct', wally_words], ['string']], false);
Module.bip39_mnemonic_to_seed = _wrap_resolve_args('bip39_mnemonic_to_seed', [['string'], ['string'], ['out_buffer', Module.BIP39_SEED_LEN_512, true]]);

//wally_script
Module.scriptpubkey_get_type = _wrap_resolve_args('wally_scriptpubkey_get_type', [['in_buffer'], ['ptr_val', 'i32']]);
Module.scriptpubkey_p2pkh_from_bytes = _wrap_resolve_args('wally_scriptpubkey_p2pkh_from_bytes', [['in_buffer'], ['number'], ['out_buffer', Module.HASH160_LEN + 5, true]]);
Module.scriptsig_p2pkh_from_sig = _wrap_resolve_args('wally_scriptsig_p2pkh_from_sig', [['in_buffer'], ['in_buffer'], ['number'], ['out_buffer', Module.EC_SIGNATURE_DER_MAX_LEN + Module.EC_PUBLIC_KEY_LEN + 2, true]]);
Module.scriptsig_p2pkh_from_der = _wrap_resolve_args('wally_scriptsig_p2pkh_from_der', [['in_buffer'], ['in_buffer'], ['out_buffer', Module.EC_SIGNATURE_DER_MAX_LEN + Module.EC_PUBLIC_KEY_LEN + 2, true]]);
Module.scriptpubkey_op_return_from_bytes = _wrap_resolve_args('wally_scriptpubkey_op_return_from_bytes', [['in_buffer'], ['number'], ['out_buffer', Module.WALLY_SCRIPTPUBKEY_OP_RETURN_MAX_LEN, true]]);
Module.scriptpubkey_p2sh_from_bytes = _wrap_resolve_args('wally_scriptpubkey_p2sh_from_bytes', [['in_buffer'], ['number'], ['out_buffer', Module.HASH160_LEN + 3, true]]);
Module.scriptpubkey_multisig_from_bytes = _wrap_resolve_args('wally_scriptpubkey_multisig_from_bytes', [['byte_array'], ['number'], ['number'], ['out_buffer', (pks) => (3 + pks.length * (1 + Module.EC_PUBLIC_KEY_LEN)), true]]);
Module.scriptsig_multisig_from_bytes = _wrap_resolve_args('wally_scriptsig_multisig_from_bytes', [['in_buffer'], ['byte_array'], ['int_array'], ['number'], ['out_buffer', (redeem, sigs) => (4 + redeem.length + sigs.length * (1 + Module.EC_SIGNATURE_DER_MAX_LEN)), true]]);
const _wally_script_push_from_bytes_len = (bytes, flags) => {
    if (flags & Module.WALLY_SCRIPT_HASH160) {
        return Module.HASH160_LEN + 1;
    } else if (flags & Module.WALLY_SCRIPT_SHA256) {
        return Module.SHA256_LEN + 1;
    }

    let push_len = bytes.length;
    let opcode_len = 5;
    for ([l, op_len] of [[76, 1], [256, 2], [65536, 3]]) {
        if (push_len < l) {
            opcode_len = op_len;
            break;
        }
    }

    return push_len + opcode_len;
}
Module.script_push_from_bytes = _wrap_resolve_args('wally_script_push_from_bytes', [['in_buffer'], ['number'], ['out_buffer', _wally_script_push_from_bytes_len , true]]);
Module.witness_program_from_bytes = _wrap_resolve_args('wally_witness_program_from_bytes', [['in_buffer'], ['number'], ['out_buffer', Module.WALLY_WITNESSSCRIPT_MAX_LEN , true]]);

// wally_transaction
class wally_tx_input extends _wrapped_struct {
    constructor(ptr) {
        super('wally_tx_input', 'wally_tx_input_free', ptr);
    }
}
class wally_tx_output extends _wrapped_struct {
    constructor(ptr) {
        super('wally_tx_output', 'wally_tx_output_free', ptr);
    }
}
class wally_tx extends _wrapped_struct {
    constructor(ptr) {
        super('wally_tx', 'wally_tx_free', ptr);
    }
}
class wally_tx_witness_stack extends _wrapped_struct {
    constructor(ptr) {
        super('wally_tx_witness_stack', 'wally_tx_witness_stack_free', ptr);
    }
}
Module.tx_witness_stack_init = _wrap_resolve_args('wally_tx_witness_stack_init_alloc', [['number'], ['out_struct', wally_tx_witness_stack]]);
Module.tx_witness_stack_add = _wrap_resolve_args('wally_tx_witness_stack_add', [['in_struct', wally_tx_witness_stack], ['in_buffer']]);
Module.tx_witness_stack_add_dummy = _wrap_resolve_args('wally_tx_witness_stack_add_dummy', [['in_struct', wally_tx_witness_stack], ['number']]);
Module.tx_witness_stack_set = _wrap_resolve_args('wally_tx_witness_stack_set', [['in_struct', wally_tx_witness_stack], ['number'], ['in_buffer']]);
Module.tx_witness_stack_set_dummy = _wrap_resolve_args('wally_tx_witness_stack_set_dummy', [['in_struct', wally_tx_witness_stack], ['number'], ['number']]);
Module.tx_input_init = _wrap_resolve_args('wally_tx_input_init_alloc', [['in_buffer'], ['number'], ['number'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['out_struct', wally_tx_input]]);
Module.tx_output_init = _wrap_resolve_args('wally_tx_output_init_alloc', [['number'], ['in_buffer'], ['out_struct', wally_tx_output]]);
Module.tx_init = _wrap_resolve_args('wally_tx_init_alloc', [['number'], ['number'], ['number'], ['number'], ['out_struct', wally_tx]]);
Module.tx_add_input = _wrap_resolve_args('wally_tx_add_input', [['in_struct', wally_tx], ['in_struct', wally_tx_input]]);
Module.tx_add_raw_input = _wrap_resolve_args('wally_tx_add_raw_input', [['in_struct', wally_tx], ['in_buffer'], ['number'], ['number'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['number']]);
Module.tx_remove_input = _wrap_resolve_args('wally_tx_remove_input', [['in_struct', wally_tx], ['number']]);
Module.tx_set_input_script = _wrap_resolve_args('wally_tx_set_input_script', [['in_struct', wally_tx], ['number'], ['in_buffer']]);
Module.tx_set_input_witness = _wrap_resolve_args('wally_tx_set_input_witness', [['in_struct', wally_tx], ['number'], ['in_struct', wally_tx_witness_stack]]);
Module.tx_add_output = _wrap_resolve_args('wally_tx_add_output', [['in_struct', wally_tx], ['in_struct', wally_tx_output]]);
Module.tx_add_raw_output = _wrap_resolve_args('wally_tx_add_raw_output', [['in_struct', wally_tx], ['in_bigint'], ['in_buffer'], ['number']]);
Module.tx_remove_output = _wrap_resolve_args('wally_tx_remove_output', [['in_struct', wally_tx], ['number']]);
Module.tx_get_witness_count = _wrap_resolve_args('wally_tx_get_witness_count', [['in_struct', wally_tx], ['ptr_val', 'i32']]);
Module.tx_get_length = _wrap_resolve_args('wally_tx_get_length', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i32']]);
Module.tx_from_bytes = _wrap_resolve_args('wally_tx_from_bytes', [['in_buffer'], ['number'], ['out_struct', wally_tx]]);
Module.tx_from_hex = _wrap_resolve_args('wally_tx_from_hex', [['string'], ['number'], ['out_struct', wally_tx]]);
Module.tx_to_bytes = _wrap_resolve_args('wally_tx_to_bytes', [['in_struct', wally_tx], ['number'], ['out_buffer', (tx, flags) => wally_tx_get_length(tx, flags), true]]);
Module.tx_to_hex = _wrap_resolve_args('wally_tx_to_hex', [['in_struct', wally_tx], ['number'], ['out_string']]);
Module.tx_get_weight = _wrap_resolve_args('wally_tx_get_weight', [['in_struct', wally_tx], ['ptr_val', 'i32']]);
Module.tx_get_vsize = _wrap_resolve_args('wally_tx_get_vsize', [['in_struct', wally_tx], ['ptr_val', 'i32']]);
Module.tx_vsize_from_weight = _wrap_resolve_args('wally_tx_vsize_from_weight', [['number'], ['ptr_val', 'i32']]);
Module.tx_get_total_output_satoshi = _wrap_resolve_args('wally_tx_get_total_output_satoshi', [['in_struct', wally_tx], ['ptr_val', 'i64']]);
Module.tx_get_btc_signature_hash = _wrap_resolve_args('wally_tx_get_btc_signature_hash', [['in_struct', wally_tx], ['number'], ['in_buffer'], ['in_bigint'], ['number'], ['number'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_get_signature_hash = _wrap_resolve_args('wally_tx_get_signature_hash', [['in_struct', wally_tx], ['number'], ['in_buffer'], ['in_buffer'], ['number'], ['number'], ['number'], ['number'], ['number'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_is_coinbase = _wrap_resolve_args('wally_tx_is_coinbase', [['in_struct', wally_tx], ['ptr_val', 'i32']]);
Module.tx_elements_input_issuance_set = _wrap_resolve_args('wally_tx_elements_input_issuance_set', [['in_struct', wally_tx_input], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer']]);
Module.tx_elements_input_issuance_free = _wrap_resolve_args('wally_tx_elements_input_issuance_free', [['in_struct', wally_tx_input]]);
Module.tx_elements_input_init = _wrap_resolve_args('wally_tx_elements_input_init_alloc', [['in_buffer'], ['number'], ['number'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['out_struct', wally_tx_input]]);
Module.tx_elements_input_is_pegin = _wrap_resolve_args('wally_tx_elements_input_is_pegin', [['in_struct', wally_tx_input], ['ptr_val', 'i32']]);
Module.tx_elements_output_commitment_set = _wrap_resolve_args('wally_tx_elements_output_commitment_set', [['in_struct', wally_tx_output], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer']]);
Module.tx_elements_output_commitment_free = _wrap_resolve_args('wally_tx_elements_output_commitment_free', [['in_struct', wally_tx_output]]);
Module.tx_elements_output_init = _wrap_resolve_args('wally_tx_elements_output_init_alloc', [['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['out_struct', wally_tx_output]]);
Module.tx_add_elements_raw_input = _wrap_resolve_args('wally_tx_add_elements_raw_input', [['in_struct', wally_tx], ['in_buffer'], ['number'], ['number'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_struct', wally_tx_witness_stack], ['out_struct', wally_tx_input], ['number']]);
Module.tx_add_elements_raw_output = _wrap_resolve_args('wally_tx_add_elements_raw_output', [['in_struct', wally_tx], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['in_buffer'], ['out_struct', wally_tx_output], ['number']]);
Module.tx_is_elements = _wrap_resolve_args('wally_tx_is_elements', [['in_struct', wally_tx], ['ptr_val', 'i32']]);
Module.tx_confidential_value_from_satoshi = _wrap_resolve_args('wally_tx_confidential_value_from_satoshi', [['in_bigint'], ['out_buffer', Module.WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN]]);
Module.tx_confidential_value_to_satoshi = _wrap_resolve_args('wally_tx_confidential_value_to_satoshi', [['in_buffer'], ['ptr_val', 'i64']]);
Module.tx_get_elements_signature_hash = _wrap_resolve_args('wally_tx_get_elements_signature_hash', [['in_struct', wally_tx], ['number'], ['in_buffer'], ['in_buffer'], ['number'], ['number'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_elements_issuance_generate_entropy = _wrap_resolve_args('wally_tx_elements_issuance_generate_entropy', [['in_buffer'], ['number'], ['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_elements_issuance_calculate_asset = _wrap_resolve_args('wally_tx_elements_issuance_calculate_asset', [['in_buffer'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_elements_issuance_calculate_reissuance_token = _wrap_resolve_args('wally_tx_elements_issuance_calculate_reissuance_token', [['in_buffer'], ['number'], ['out_buffer', Module.SHA256_LEN]]);
// getters
Module.tx_get_input_txhash = _wrap_resolve_args('wally_tx_get_input_txhash', [['in_struct', wally_tx], ['number'], ['out_buffer', Module.SHA256_LEN]]);
Module.tx_get_input_index = _wrap_resolve_args('wally_tx_get_input_index', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i32']]);
Module.tx_get_input_sequence = _wrap_resolve_args('wally_tx_get_input_sequence', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i32']]);
Module.tx_get_input_script_len = _wrap_resolve_args('wally_tx_get_input_script_len', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i32']]);
Module.tx_get_input_script = _wrap_resolve_args('wally_tx_get_input_script', [['in_struct', wally_tx], ['number'], ['out_buffer', (tx, vin) => Module.tx_get_input_script_len(tx, vin), true]]);
Module.tx_get_input_witness_len = _wrap_resolve_args('wally_tx_get_input_witness_len', [['in_struct', wally_tx], ['number'], ['number'], ['ptr_val', 'i32']]);
Module.tx_get_input_witness = _wrap_resolve_args('wally_tx_get_input_witness', [['in_struct', wally_tx], ['number'], ['number'], ['out_buffer', (tx, vin, windex) => Module.tx_get_input_witness_len(tx, vin, windex), true]]);
Module.tx_get_output_script_len = _wrap_resolve_args('wally_tx_get_output_script_len', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i32']]);
Module.tx_get_output_script = _wrap_resolve_args('wally_tx_get_output_script', [['in_struct', wally_tx], ['number'], ['out_buffer', (tx, vin) => Module.tx_get_output_script_len(tx, vin), true]]);
Module.tx_get_output_satoshi = _wrap_resolve_args('wally_tx_get_output_satoshi', [['in_struct', wally_tx], ['number'], ['ptr_val', 'i64']]);

let wally_begin = () => {};
Module.ready_promise = new Promise((resolve, reject) => {
    wally_begin = () => {
        wally_init(0);

        wally_ready = true;
        resolve();
    };
});

if (!Module.postRun) {
    Module.postRun = [];
}
Module.postRun.unshift(wally_begin);
