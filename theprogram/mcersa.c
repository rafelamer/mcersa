#include <mce/mcersa.h>
#include <stdlib.h>
#include "cmdline.h"

int main(int argc, char **argv)
{
	int ret;
	static struct gengetopt_args_info ai;
	static char keyName[] = "id_rsa";

	ret = EXIT_FAILURE;
	if (cmdline_parser(argc, argv, &ai) != 0) {
		fprintf(stderr, "Error reading the command line parameters\n");
		goto final;
	}
	if (ai.help_given) {
		printf("%s\n", gengetopt_args_info_usage);
		printf("%s\n", *gengetopt_args_info_help);
		ret = EXIT_SUCCESS;
		goto final;
	}
	/*
	   Process the different options
	   1. Generate a pair of public and private key
	 */
	if (ai.genkey_flag) {
		int bits;
		char *name;

		if (ai.infile_given || ai.encrypt_given || ai.decrypt_given ||
		    ai.ascii_given || ai.keyfile_given || ai.sign_flag ||
		    ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}

		bits = ai.bits_arg;
		if (bits > 8192)
			bits = 8192;

		if (ai.outfile_given)
			name = ai.outfile_arg;
		else
			name = keyName;
		if (generatePairRSAKeys(bits,name,!ai.noaes_flag)) {
			printf
			    ("Public private RSA key pair generated successfully\n");
			ret = EXIT_SUCCESS;
		} else {
			fprintf(stderr,
				"Error generating a private public RSA key pair\n");
		}
		goto final;
	}

	/*
	   2.1 Encrypts a file with the symetric algorithm AES
	 */
	if (ai.encrypt_flag && (!ai.keyfile_given)) {
		char *infile, *outfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,
				"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}

		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		r = encryptFileWithAES(infile, &outfile, ai.ascii_flag);
		if (r == ENCRYPTION_OK) {
			printf
			    ("File encrypted successfuly. Encrypted file is %s\n",
			     outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read",
				infile);
		else if (r == ENCRYPTION_WRONG_PASSWORD)
			fprintf(stderr,
				"The two passphrases does not coincide. Try again\n");
		else if (r == ENCRYPTION_ERROR)
			fprintf(stderr,
				"Some error ocurred while encrypting the file %s\n",
				infile);
		else if (r == ENCRYPTION_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",
				outfile);
		else if (r == ENCRYPTION_PASSWORD_SHORT)
			fprintf(stderr,
				"Passphrase too short. It must have at least 8 characters\n");

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}

	/*
	   2.2 Encrypts a file using an RSA public key
	 */
	if (ai.encrypt_flag && ai.keyfile_given) {
		char *infile, *outfile, *keyfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,
				"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}
		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		r = encryptFileWithRSA(infile, &outfile, keyfile, ai.ascii_flag);
		if (r == ENCRYPTION_OK) {
			printf
			    ("File encrypted successfuly. Encrypted file is %s\n",
			     outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read",
				infile);
		else if (r == ENCRYPTION_ERROR)
			fprintf(stderr,
				"Some error ocurred while encrypting the file %s\n",
				infile);
		else if (r == ENCRYPTION_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",
				outfile);
		else if (r == ENCRYPTION_PUBLIC_KEY_ERROR)
			fprintf(stderr,
				"Error opening the public key file %s\n",
				keyfile);

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}

	/*
	   3.1 Decrypts a file with the symetric algorithm AES
	 */
	if (ai.decrypt_flag && (!ai.keyfile_given)) {
		char *infile, *outfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,
				"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}
		if (!ai.outfile_given) {
			fprintf(stderr,
				"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}

		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}

		infile = ai.infile_arg;
		outfile = ai.outfile_arg;
		r = decryptFileWithAES(infile, outfile);
		if (r == ENCRYPTION_OK) {
			printf
			    ("File decrypted successfuly. Decrypted file is %s\n",
			     outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read",
				infile);
		else if (r == ENCRYPTION_ERROR)
			fprintf(stderr,
				"Some error ocurred while decrypting the file %s\n",
				infile);
		else if (r == ENCRYPTION_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",
				outfile);
		else if (r == ENCRYPTION_WRONG_PASSWORD)
			fprintf(stderr,
				"You have entered a wrong passphrase three tines\n");

		goto final;
	}

	/*
	   3.2 Decrypts a file encrypted with a private RSA key
	 */
	if (ai.decrypt_flag && ai.keyfile_given) {
		char *infile, *outfile, *keyfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,
				"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}
		if (!ai.outfile_given) {
			fprintf(stderr,
				"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}

		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}

		infile = ai.infile_arg;
		outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		r = decryptFileWithRSA(infile, outfile, keyfile);
		if (r == ENCRYPTION_OK) {
			printf
			    ("File decrypted successfuly. Decrypted file is %s\n",
			     outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read",
				infile);
		else if (r == ENCRYPTION_ERROR)
			fprintf(stderr,
				"Some error ocurred while decrypting the file %s\n",
				infile);
		else if (r == ENCRYPTION_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",
				outfile);
		else if (r == ENCRYPTION_PRIVATE_KEY_ERROR)
			fprintf(stderr,
				"Error opening the private key file %s\n",
				keyfile);

		goto final;
	}

	/*
		4.1 Encrypts an unencrypted RSA private key file
	*/
	if (ai.encryptkey_flag && ai.keyfile_given) {
		char *infile, *outfile;
		PrivateRSAKey rsa;
		rsa = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,
				"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		if ((rsa = bdReadPrivateRSAKeyFromFile(infile)) == NULL) {
			fprintf(stderr,
				"Error reading the unencrypted private RSA key %s\n",infile);
			goto final;
		}
		if (! bdWriteEncryptedPrivateRSAKeyToFile(outfile,rsa))
			fprintf(stderr,
				"Error writing the encrypted private RSA key %s\n",outfile);

		freePrivateRSAKey(rsa);
		goto final;			
	}

	/*
		4.2 Decrypts an encrypted RSA private key file
	*/
	if (ai.decryptkey_flag && ai.keyfile_given) {
		char *infile, *outfile;
		PrivateRSAKey rsa;
		rsa = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,
				"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		if ((rsa = bdReadEncryptedPrivateRSAKeyFromFile(infile)) == NULL) {
			fprintf(stderr,
				"Error reading the encrypted private RSA key %s\n",infile);
			goto final;
		}
		if (! bdWritePrivateRSAKeyToFile(outfile,rsa))
			fprintf(stderr,
				"Error writing the unencrypted private RSA key %s\n",outfile);

		freePrivateRSAKey(rsa);
		goto final;			
	}

	/*
		5.1 Signs a file
	*/
	if(ai.sign_flag && ai.infile_given && ai.keyfile_given)
	{
		char *infile, *outfile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		r = signFileWithRSA(infile,&outfile,keyfile,ai.ascii_flag);
		if (r == SIGNATURE_OK) {
			printf
			    ("File signed successfuly. Signed file is %s\n",
			     outfile);
			ret = EXIT_SUCCESS;
		} else if (r == SIGNATURE_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read",
				infile);
		else if (r == SIGNATURE_ERROR)
			fprintf(stderr,
				"Some error ocurred while signing the file %s\n",
				infile);
		else if (r == SIGNATURE_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",
				outfile);
		else if (r == ENCRYPTION_PRIVATE_KEY_ERROR)
			fprintf(stderr, "Error reading the private key file %s\n",
				keyfile);

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}

	/*
		5.2 Extract and verify a signed file
	*/
	if(ai.verify_flag && ai.infile_given && ai.keyfile_given)
	{
		char *infile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.sign_flag || ai.ascii_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		keyfile = ai.keyfile_arg;
		r = verifyAndExtractSignedFileWithRSA(infile,keyfile);
		if (r == SIGNATURE_OK) {
			printf
			    ("File %s verified and extracted successfuly\n",infile);
			ret = EXIT_SUCCESS;
		} 
		else if (r == SIGNATURE_BAD)
			fprintf(stderr,
				"The file %s has in incorrect signature\n",
				infile);
		else if (r == SIGNATURE_FILE_NOT_FOUND)
			fprintf(stderr,
				"The file %s was not found or can not be read\n",
				infile);
		else if (r == SIGNATURE_ERROR)
			fprintf(stderr,
				"Some error ocurred while verifying the file %s\n",
				infile);
		else if (r == SIGNATURE_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile");
		else if (r == ENCRYPTION_PUBLIC_KEY_ERROR)
			fprintf(stderr, "Error reading the public key file %s\n",
				keyfile);
		else if (r == ENCRYPTION_WRITE_FILE_ERROR)
			fprintf(stderr, "Error writing the outfile");
		goto final;
	}

	/*
	   Final of the program
	 */
	printf("%s\n", gengetopt_args_info_usage);
	printf("%s\n", *gengetopt_args_info_help);
	ret = EXIT_SUCCESS;

 final:
	cmdline_parser_free(&ai);
	return ret;
}
