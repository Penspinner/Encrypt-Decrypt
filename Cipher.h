#ifndef CIPHER_H

	#define CIPHER_H

	#define BUFFER_SIZE 256
	#define ALPHABET_SIZE 26
	#define KEY_SIZE 256

	/**
	 * Can use this array to store your plaintext
	 * messages for encryption/decryption.
	 */
	char plaintext[BUFFER_SIZE];

	/**
	 * Can use this array to store your ciphertext
	 * for encryption.decryption.
	 */
	char ciphertext[BUFFER_SIZE];

	/**
	 * Can use this array to store your key that is
	 * used for encryption.decryption.
	 */
	char key[KEY_SIZE];

	/**
	 * Should store your alphabet for the substitution cipher.
	 */
	char alphabet[ALPHABET_SIZE];

	/**
	 * Should store your tabula recta for the autokey cipher.
	 */
	char tabula[ALPHABET_SIZE][ALPHABET_SIZE];

	/**
	 * Additional place you might want to use. Don't have too.
	 * You can use some casting magic to change type from char 
	 * if you need too.
	 */
	char buffer[BUFFER_SIZE];

	/********** Function prototypes **********/

	/**
	 * This prints out the header to show the usage of the program.
	 */
	void printHeader();

	/**
	 * This function will encrypt/decrypt the text given in the file/stdin
	 * using substitution cipher.
	 */
	void substitution(int argc, char **argv, int e, int d);

	/**
	 * This function will shift the bits of the text left/right depending
	 * on encryption/decryption.
	 */
	void shift(int shamt, int e, int d, char *text, char *encryptedText);

	/**
	 * This function will make the parameter text all upper case.
	 */
	void upperCasify(char *text);

	/**
	 * This function will encrypt/decrypt the text given in the file/stdin
	 * using autokey cipher.
	 */
	void autokey(int argc, char **argv, int e, int d);

	/**
	 * This function will create a KEY to encrypt/decrypt text. The key 
	 * should be saved to know how to reformat the text back to regular.
	 */
	void createKey();

	/**
	 * Stores the whole alphabet in the alphabet array.
	 */
	void createAlphabet();

	/**
	 * Constructs the tabula recta to show what the program will use for
	 * autokey cipher.
	 */
	void constructTabulaRecta(int n, int e, int d);

	/**
	 * Prints out the tabula recta.
	 */
	void printTabulaRecta();

	/**
	 * This function will encrypt the text letter by letter.
	 */
	void cipher(int e, int d, char *text, char *k, char *encryptedText);

	/**
	 * This function will read the file entered into stdin and store 
	 * the text of the file into the text variable.
	 */
	void readFile(char *fileName, char *text);

	/**
	 * This function will produce a file with the given fileName and 
	 * write the text into the file.
	 */
	void writeFile(char *fileName, char *text);

#endif
