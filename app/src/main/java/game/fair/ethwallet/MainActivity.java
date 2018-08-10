package game.fair.ethwallet;

import android.content.Context;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.web3j.crypto.Bip39Wallet;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.WalletUtils;
import org.web3j.utils.Strings;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;


import game.fair.ethwallet.wallet.MyWalletUtil;


/**
 * @author Administrator
 */
public class MainActivity extends AppCompatActivity {
    private Button btnCreateWallet;
    private EditText edtMnemonic;
    private EditText edtPkey;
    private EditText edtKeyStore;
    private Button btnMnemonicImport;
    private Button btnPkeyImport;
    private Button btnKeyStoreImport;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        init();
    }

    private void init() {
        btnCreateWallet = findViewById(R.id.create_wallet_btn);
        btnCreateWallet.setOnClickListener(view -> {
            createETHWalletFromWords();
        });

        edtMnemonic = findViewById(R.id.mnemonic_edt);
        edtKeyStore = findViewById(R.id.ketstore_edt);
        edtPkey = findViewById(R.id.pkey_edt);
        btnMnemonicImport = findViewById(R.id.import_wallet_mnemonic_btn);
        btnPkeyImport = findViewById(R.id.import_wallet_pkey_btn);
        btnKeyStoreImport  =findViewById(R.id.import_wallet_ketstore_btn);

        btnMnemonicImport.setOnClickListener(v -> {
            String mnemonicStr = edtMnemonic.getText().toString();
            this.importWalletFromMnemonic(mnemonicStr);
        });

        btnPkeyImport.setOnClickListener(v -> {
            String pkeyStr = edtPkey.getText().toString();
            this.importWalletFromPkey(pkeyStr);
        });

        btnKeyStoreImport.setOnClickListener(v -> {
            String keyStoreStr = edtKeyStore.getText().toString();
            this.importWalletFromKeyStore(keyStoreStr);
        });
    }


    private void createETHWalletFromWords() {
        new Thread(() -> {
            try {
                Bip39Wallet wallet = MyWalletUtil.generateBip39Wallet("123456",
                        new File(Environment.getExternalStorageDirectory().getPath() + "/"));
                Log.i(wallet.getFilename(), wallet.getMnemonic());
            } catch (CipherException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
        /*ThreadFactory namedThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("demo-pool-%d").build();
        ExecutorService singleThreadPool = new ThreadPoolExecutor(1, 1,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<Runnable>(1024), namedThreadFactory, new ThreadPoolExecutor.AbortPolicy());

        singleThreadPool.execute(()-> System.out.println(Thread.currentThread().getName()));
        singleThreadPool.shutdown();*/
    }

    private void importWalletFromMnemonic(String mnemonic) {
        if (Strings.isEmpty(mnemonic)) {
            Toast.makeText(this,"请输入助记词",Toast.LENGTH_SHORT).show();
            return;
        }
        Credentials credentials =  WalletUtils.loadBip39Credentials("123456",mnemonic);
        Log.i("MyWalletUtil",
                "\nAddress:" + credentials.getAddress() + "\n" +
                        "privateKey:" + credentials.getEcKeyPair().getPrivateKey().toString(16) + "\n" +
                        "publicKey:" + credentials.getEcKeyPair().getPublicKey() + "\n" +
                        "助记词:" + mnemonic);
    }

    private void importWalletFromPkey(String pKey) {
        if (Strings.isEmpty(pKey)) {
            Toast.makeText(this,"请输入私钥",Toast.LENGTH_SHORT).show();
            return;
        }
        ECKeyPair ecKeyPair = ECKeyPair.create(new BigInteger(pKey,16));
        Log.i("MyWalletUtil",
                "\nAddress:" + Keys.getAddress(ecKeyPair) + "\n" +
                        "privateKey:" + ecKeyPair.getPrivateKey().toString(16) + "\n" +
                        "publicKey:" + ecKeyPair.getPublicKey() + "\n" +
                        "助记词:" + "");
    }
    //77218515539933930938042947747821301429796048116772966871170454767662017071972
    //77218515539933930938042947747821301429796048116772966871170454767662017071972
    //
    //904B53246A7AC5E91A0DA9C638CF3C026FFF9B79A28A5BE624F9FBD535D9F72C
    private void importWalletFromKeyStore(String keyStore) {
        if (Strings.isEmpty(keyStore)) {
            Toast.makeText(this,"请输入keyStore",Toast.LENGTH_SHORT).show();
            return;
        }
    }
}
