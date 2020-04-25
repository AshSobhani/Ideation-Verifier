package com.example.ideationverifier;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class MainActivity extends AppCompatActivity {
	private static final String TAG = "MainActivity";
	private static final int PICK_FILE_REQUEST = 1;

	//Initialise variables
	private TextView fileName;
	private EditText publicKeyText, signatureText;
	private Button verifyButton;
	private byte[] pdfInBytes = null;
	private String name;

	//Declare a URI for the PDF
	private Uri fileUri;

	// Storage Permissions
	private static final int REQUEST_EXTERNAL_STORAGE = 1;
	private static String[] PERMISSIONS_STORAGE = {
			Manifest.permission.READ_EXTERNAL_STORAGE,
			Manifest.permission.WRITE_EXTERNAL_STORAGE
	};

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		//Set views to variables
		publicKeyText = findViewById(R.id.publicKeyText);
		signatureText = findViewById(R.id.signatureText);
		fileName = findViewById(R.id.fileName);
		verifyButton = findViewById(R.id.verifyButton);

	}

	public void onChooseFile(View v) {
		//Check storage permissions
		verifyStoragePermissions(this);

		//Open file manager to select NDA
		//Create a new intent looking for PDF files and start it
		Intent intent = new Intent();
		intent.setType("application/pdf");
		intent.setAction(Intent.ACTION_GET_CONTENT);
		startActivityForResult(intent, PICK_FILE_REQUEST);
	}

	@RequiresApi(api = Build.VERSION_CODES.O)
	public void onVerifySignature(View v) {
		//Get the public key
		String encodedPublicKeyString = publicKeyText.getText().toString();
		//Decode public key string back into bytes
		byte[] encodedPublicKey = Base64.decode(encodedPublicKeyString, Base64.NO_WRAP);

		//Get the signature
		String encodedSignature = signatureText.getText().toString();
		//Decode the signature
		byte[] signedNDAFile = Base64.decode(encodedSignature, 2);

		//Get the file bytes and hash them
		byte[] fileBytes = getFileBytes();
		byte[] hashedNDAFile = hashNDAFile(fileBytes);

		verifySignedNDAFile(encodedPublicKey, hashedNDAFile, signedNDAFile);
	}

	public String verifySignedNDAFile(byte[] encodedPublicKey, byte[] hashedNDAFile, byte[] signedNDA) {
		//Initialise variables
		boolean verified = false;
		String encodedSignature = null;

		try {
			//GET THE USERS PUBLIC KEY
			//Takes your byte array of the key as constructor parameter
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
			//Takes algorithm used (RSA) to generate keys
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			//Creates a new PublicKey object
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			//VERIFY THE SIGNATURE
			//Initialise a signature and get SHA512 with RSA instance
			Signature verificationSignature = Signature.getInstance("SHA512withRSA");
			//Add the public key
			verificationSignature.initVerify(publicKey);
			//Add the hashed data to the signature
			verificationSignature.update(hashedNDAFile);
			//Check if its verified
			verified = verificationSignature.verify(signedNDA);

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

		//If it verifies return the encoded signature to store in request document else return fail
		if (verified) {
			Log.d(TAG, "verifiedDeviceSignature: Verified");
			Toast.makeText(MainActivity.this, "VERIFIED", Toast.LENGTH_SHORT).show();

			//Encode the signature so it can be stored and return
			encodedSignature = new String(Base64.encode(signedNDA, 2));
			return encodedSignature;
		} else {
			Log.d(TAG, "verifiedDeviceSignature: Not Verified");
			Toast.makeText(MainActivity.this, "FAILED", Toast.LENGTH_SHORT).show();
			return "Verification Failed";
		}
	}

	@RequiresApi(api = Build.VERSION_CODES.O)
	private byte[] getFileBytes() {
		//Create the file directory
		String fileDirectory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS) + "/" + name;

		Log.d(TAG, "onChooseFile: " + fileDirectory);

		//Parse the directory and create a path
		Uri uri = Uri.parse(fileDirectory);
		Path filePath = Paths.get(uri.getPath());

		try
		{
			//Convert the file into bytes and store in variable
			pdfInBytes = Files.readAllBytes(filePath);

			//Check if the bytes give back the PDF
			//checkBytesToPDF(pdfInBytes);

			return pdfInBytes;
		} catch (FileNotFoundException ex) {
			System.out.print("File not found");
			return null;
		} catch(AccessDeniedException e) {
			System.out.print("File access denied");
			Log.d(TAG, "onActivityResult: File access denied");
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public byte[] hashNDAFile(byte[] pdfInBytes) {
		//Initialise digest
		MessageDigest digest = null;

		//Get the SHA512 message digest instance
		try {
			digest = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		//Make sure there are bytes to hash
		if (pdfInBytes != null) {
			//Apply the digest to the data to hash the data
			digest.update(pdfInBytes);
			byte[] hashedNDAFile = digest.digest();

			Toast.makeText(MainActivity.this, "Good bytes", Toast.LENGTH_SHORT).show();

			//Return hashed NDA file
			return hashedNDAFile;
		} else {
			//If there are no bytes then return null
			Toast.makeText(MainActivity.this, "No bytes", Toast.LENGTH_SHORT).show();
			return null;
		}
	}

	private void checkBytesToPDF(byte[] pdfInBytes) throws IOException {
		//Chose file name and location
		File outFile = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getPath() + "/" + "BytesToNDA" + ".pdf");

		//Use the bytes and to populate the file
		OutputStream out = new FileOutputStream(outFile);
		out.write(pdfInBytes);
		out.close();
	}

	public static void verifyStoragePermissions(Activity activity) {
		// Check if we have write permission
		int permission = ActivityCompat.checkSelfPermission(activity, Manifest.permission.WRITE_EXTERNAL_STORAGE);

		if (permission != PackageManager.PERMISSION_GRANTED) {
			// We don't have permission so prompt the user
			ActivityCompat.requestPermissions(
					activity,
					PERMISSIONS_STORAGE,
					REQUEST_EXTERNAL_STORAGE
			);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);

		//If a file has been selected and its ok add it to the file uri variable
		if (requestCode == PICK_FILE_REQUEST && resultCode == RESULT_OK
				&& data != null && data.getData() != null) {
			//Get the file data
			fileUri = data.getData();

			//Create a cursor to browse data
			Cursor cursor = getContentResolver().query(fileUri, null, null, null, null);
			int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
			cursor.moveToFirst();

			//Get the name and set the text
			name = cursor.getString(nameIndex);
			fileName.setText(name);

			//Enable the button and allow them to agree to the NDA
			verifyButton.setEnabled(true);
			verifyButton.setTextColor(Color.parseColor("#00ccff"));
		}
	}
}
