const expect = require('chai').expect;
const Util = require('../lib/Util');
const ChaCha20 = require('../lib/ChaCha20');
const HChaCha20 = require('../lib/HChaCha20');
const XChaCha20 = require('../lib/XChaCha20');

let c = new ChaCha20();
let h = new HChaCha20();
let x = new XChaCha20();

describe('Test Vectors', function () {
    it('ChaCha20 Addition', function () {
        expect(0).to.be.equal(c.add(0xffffffff, 1));
        expect(0xffffffff).to.be.equal(c.add(0xfffffffe, 1));
        expect(0x80000000).to.be.equal(c.add(0x7fffffff, 1));
    });

    it('ChaCha20 Rotation', function () {
        let rot = ChaCha20.rotate(parseInt('ffff0000', 16), 16);
        expect('ffff').to.be.equal(rot.toString(16));

        rot = ChaCha20.rotate(parseInt('ffff0000', 16), 32);
        expect('ffff0000').to.be.equal(rot.toString(16));

        rot = ChaCha20.rotate(parseInt('ffff0000', 16), 24);
        expect('ffff00').to.be.equal(rot.toString(16));

        rot = ChaCha20.rotate(parseInt('ffff0000', 16), 8);
        expect('ff0000ff').to.be.equal(rot.toString(16));

        rot = ChaCha20.rotate(parseInt('ffff0000', 16), 15);
        expect('80007fff').to.be.equal(rot.toString(16));

        rot = ChaCha20.rotate(parseInt('ffff0000', 16), 14);
        expect('c0003fff').to.be.equal(rot.toString(16));
    });

    it('ChaCha20 XOR', function () {
        expect(255).to.be.equal(c.xor(0, 255));
        expect(0).to.be.equal(c.xor(255, 255));
        expect(1).to.be.equal(c.xor(255, 254));
        expect(2).to.be.equal(c.xor(255, 253));
        expect(3).to.be.equal(c.xor(255, 252));
        expect(4).to.be.equal(c.xor(255, 251));
        expect(33).to.be.equal(c.xor(100, 69));
    });

    it('ChaCha20 Quarter Round Function', function () {
        let key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
        let nonce = Buffer.from('000000090000004a0000000031415927', 'hex');
        let ctx = h.createHCtx(key, nonce);
        let x0 = ctx.readInt32BE(0) >>> 0;
        let x4 = ctx.readInt32BE((4 << 2)) >>> 0;
        let x8 = ctx.readInt32BE((8 << 2)) >>> 0;
        let x12 = ctx.readInt32BE((12 << 2)) >>> 0;

        expect('61707865').to.be.equal(x0.toString(16));
        expect('3020100').to.be.equal(x4.toString(16));
        expect('13121110').to.be.equal(x8.toString(16));
        expect('9000000').to.be.equal(x12.toString(16));

        x0 = parseInt('61707865', 16);
        x4 = 128;
        x8 = 0;
        x12 = 0;
        let output = ChaCha20.quarterRound(x0, x4, x8, x12);
        expect('b78f8073').to.be.equal(output[0].toString(16));
        expect('ecb158da').to.be.equal(output[1].toString(16));
        expect('e3c6653f').to.be.equal(output[2].toString(16));
        expect('6ae103cf').to.be.equal(output[3].toString(16));
    });

    it('HChaCha20', function () {
        let key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
        let nonce = Buffer.from('000000090000004a0000000031415927', 'hex');

        expect(
            '617078653320646e79622d326b20657403020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c090000004a0000000000000027594131'
        ).to.be.equal(
            h.createHCtx(key, nonce).toString('hex')
        );

        expect(
            '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc'
        ).to.be.equal(
            h.hChaCha20Bytes(nonce, key).toString('hex')
        );
    });

    it('ChaCha20 -- test vectors (RFC 7539)', function () {
        let key = Buffer.alloc(32, 0);
        let nonce = Buffer.alloc(12, 0);
        let message;

        expect(
            c.ietfStream(64, nonce, key).toString('hex')
        ).to.be.equal(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7' +
            'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
        );

        expect(
            c.ietfStreamIc(64, nonce, key, 1).toString('hex')
        ).to.be.equal(
            '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed' +
            '29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f'
        );

        key = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
        expect(
            c.ietfStreamIc(64, nonce, key, 1).toString('hex')
        ).to.be.equal(
            '3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a' +
            '8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0'
        );

        key = Buffer.alloc(32, 0);
        nonce = Buffer.alloc(12, 0);
        message = Buffer.alloc(128, 0);
        expect(
            c.ietfStreamXorIc(message, nonce, key, 0).toString('hex')
        ).to.be.equal(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7' +
            'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586' +
            '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed' +
            '29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f'
        );

        // A.2. ChaCha20 Encryption Test Vector #2:
        key = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
        nonce = Buffer.from('000000000000000000000002', 'hex');
        message = Buffer.from(
            '416e79207375626d697373696f6e20746f20746865204945544620696e74656e' +
            '6465642062792074686520436f6e7472696275746f7220666f72207075626c69' +
            '636174696f6e20617320616c6c206f722070617274206f6620616e2049455446' +
            '20496e7465726e65742d4472616674206f722052464320616e6420616e792073' +
            '746174656d656e74206d6164652077697468696e2074686520636f6e74657874' +
            '206f6620616e204945544620616374697669747920697320636f6e7369646572' +
            '656420616e20224945544620436f6e747269627574696f6e222e205375636820' +
            '73746174656d656e747320696e636c756465206f72616c2073746174656d656e' +
            '747320696e20494554462073657373696f6e732c2061732077656c6c20617320' +
            '7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361' +
            '74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c' +
            '207768696368206172652061646472657373656420746f',
            'hex'
        );

        expect(
            c.ietfStreamXorIc(message, nonce, key, 1).toString('hex')
        ).to.be.equal(
            'a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec' +
            '2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d' +
            '4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950' +
            '42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a' +
            'd00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d' +
            'c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b' +
            '0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c' +
            'cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b' +
            'c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f' +
            '5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6' +
            '98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab' +
            '7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221'
        );

        // A.2. ChaCha20 Encryption Test Vector #3:
        key = Buffer.from('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0', 'hex');
        nonce = Buffer.from('000000000000000000000002', 'hex');
        message = Buffer.from(
            '2754776173206272696c6c69672c20616e642074686520736c6974687920746f'+
            '7665730a446964206779726520616e642067696d626c6520696e207468652077'+
            '6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665'+
            '732c0a416e6420746865206d6f6d65207261746873206f757467726162652e',
            'hex'
        );
        expect(
            c.ietfStreamXorIc(message, nonce, key, 42).toString('hex')
        ).to.be.equal(
            '62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf'+
            '166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb'+
            'f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77'+
            '04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1'
        );
    });

    // https://datatracker.ietf.org/doc/draft-arciszewski-xchacha/
    it('XChaCha20', function () {
        let key = Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex');
        let nonce = Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555658', 'hex');
        let message = Buffer.from(
            "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It" +
            " is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and" +
            " skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae."
        );
        expect(
            x.encrypt(message, nonce, key, 1).toString('hex')
        ).to.be.equal(
            '7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87'+
            'ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05'+
            '3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f'+
            '7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201'+
            '12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc'+
            '047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63'+
            'd595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73'+
            'c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4'+
            'd0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683'+
            '8a9c71f70b5b5907a66f7ea49aadc409'
        );
    })

});
