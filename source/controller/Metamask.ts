import { createHash } from 'crypto';
import {
    Body,
    JsonController,
    MethodNotAllowedError,
    Post
} from 'routing-controllers';
import { JWTAction } from '../model';
import { JsonWebTokenError } from 'jsonwebtoken';
import { MetamaskInput, MetamaskOutput } from '../model/Metamask';
import { ResponseSchema } from 'routing-controllers-openapi';

const { APP_SECRET } = process.env;

const {
    decryptVault,
    extractVaultFromFile,
    isVaultValid
} = require('../utils/lib');
const fs = require('fs');
const ethers = require('ethers');
const bip39 = require('bip39');
const Wallet = require('ethereumjs-wallet');
const util = require('ethereumjs-util');

Object.defineProperty(globalThis, 'crypto', {
    value: {
        subtle: require('crypto').subtle
    }
});

function decryptVaultRun(password, file) {
    const data = fs.readFileSync(file).toString();
    let vaultData = extractVaultFromFile(data);
    if (!vaultData || !isVaultValid(vaultData)) {
        console.log('not exact file');
        return false;
    } else {
        console.log('exact file');
        return true;
    }
}
function decryptVaultRunData(password, json) {
    let vaultData = extractVaultFromFile(JSON.stringify(json));
    if (!vaultData || !isVaultValid(vaultData)) {
        console.log('not exact file');
        return false;
    } else {
        console.log('exact file');
        return true;
    }
}

function decrypt(password, vaultData): MetamaskOutput {
    //vaultData  就是解析出的json
    //此处存在如果时liunx 文件 放到windows 上 换行问题
    return decryptVault(password, vaultData)
        .then(keyrings => {
            const serializedKeyrings = JSON.stringify(keyrings);
            //console.log('Decrypted!', serializedKeyrings);
            let addresses = { addresses: [] };
            for (const obj of keyrings) {
                if (obj.type === 'HD Key Tree') {
                    //HD
                    //console.log("HD:" + obj.type);
                    //console.log(obj.data.mnemonic);
                    // 通过助记词创建钱包对象
                    //因为时HD 助剂词 所以判断通过此助剂词生成了几个钱包地址
                    //2.将助记词转成seed
                    let seed = bip39.mnemonicToSeedSync(obj.data.mnemonic);
                    //console.log("seed：" + util.bufferToHex(seed));

                    //3.通过hdkey将seed生成HD Wallet
                    let hdWallet = Wallet.hdkey.fromMasterSeed(seed);
                    let path = "m/44'/60'/0'/0/0";
                    let key = hdWallet.derivePath(path);
                    //4.使用keypair中的公钥生成地址
                    let address = util
                        .pubToAddress(key._hdkey._publicKey, true)
                        .toString('hex');
                    //编码地址
                    address = util.toChecksumAddress('0x' + address);
                    console.log('钱包地址 (通过助记词):' + address);
                    addresses.addresses.push(address);
                } else if (obj.type === 'Simple Key Pair') {
                    //pair
                    //console.log("Pair:" + obj.type);
                    //console.log(obj.data[0]);
                    // 通过私钥创建钱包对象
                    const walletFromPrivateKey = new ethers.Wallet(obj.data[0]);
                    console.log(
                        '钱包地址 (通过私钥):',
                        walletFromPrivateKey.address
                    );

                    addresses.addresses.push(walletFromPrivateKey.address);
                }
            }
            return addresses;
        })
        .catch(reason => {
            if (reason.message === 'Incorrect password') {
                return;
            }
            console.error(reason);
        });
}

@JsonController('/metamask')
export class MetamaskController {
    store = { addresses: [] };

    static encrypt(raw: string) {
        return createHash('sha1')
            .update(APP_SECRET + raw)
            .digest('hex');
    }

    static getSession({ context: { state } }: JWTAction) {
        return state instanceof JsonWebTokenError
            ? console.error(state)
            : state;
    }

    @Post('/query')
    @ResponseSchema(MetamaskOutput)
    async query(
        @Body() { password, json }: MetamaskInput
    ): Promise<MetamaskOutput> {
        const valid = decryptVaultRunData(password, json);
        if (!valid) throw new MethodNotAllowedError();
        return decrypt(password, json);
    }
}
