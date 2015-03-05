/*
	Author: Steven Liao
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "Cipher.h"

#ifdef CSE220
	#define cse220(fmt, ...) printf("CSE220: " fmt, ##__VA_ARGS__)
	#define cse220PrintChar(char) printf("%c", char)
#else
	#define cse220(fmt, ...)
	#define cse220PrintChar(char)
#endif

/* MAIN METHOD: PROGRAM STARTS HERE */
int main(int argc, char **argv)
{	
	int s = 0, a = 0, e = 0, d = 0;
	int argument = getopt(argc, argv, "saedh");
	do
	{
		/* Perform actions */
		switch (argument)
		{
			case 's':
				s = 1;
				break;
			case 'a':
				a = 1;
				break;
			case 'e':
				e = 1;
				break;
			case 'd':
				d = 1;
				break;
			case 'h':
				printHeader();
				return EXIT_SUCCESS;
			default:
				printHeader();
				return EXIT_FAILURE;
		}
	} while ((argument = getopt(argc, argv, "saedh")) != -1);
	
	/* Check if the first two commands are valid */
	if ((s == 1 && a == 1) ||
		(s == 0 && a == 0) ||
		(e == 1 && d == 1) ||
		(e == 0 && d == 0) ||
		(s && (argc - optind) != 3) ||
		(a && (argc - optind) != 4))
	{
		printf("ERROR COMMANDS/ARGUMENTS");
		return EXIT_FAILURE;
	}

	/* Gets the first character in the third argument */
	char *c = *(argv + optind);
	int n = strtol(c, &c, 10);
	n %= ALPHABET_SIZE;
		
	if (s) 		/* Substitution */
		substitution(n, argv, e, d);
	else if (a)	/* Autokey */
		autokey(n, argv, e, d);

	return EXIT_SUCCESS;
}

void substitution(int n, char **argv, int e, int d)
{
	cse220("shift amount: %d\n", n);
	char *input = *(argv + optind + 1);
	char *output = *(argv + optind + 2);
	
	/* 	If the input file is '-' take input from stdin,
		otherwise take input from the file		*/
	if (*input == '-' && strlen(input) == 1)
	{
		cse220("input file: STD_IN\n");
		printf("Enter input: ");
		scanf("%[^\n]s", plaintext);
	} else
	{
		cse220("input file: %s\n", input);
		readFile(input, plaintext);
	}
	
	upperCasify(plaintext);
	shift(n, e, d, plaintext, ciphertext);
	
	/* 	If the output file is '-' take input from stdin,
		otherwise write to the file from that name		*/
	if (*output == '-' && strlen(output) == 1)
	{
		cse220("output file: STD_OUT\n");
		cse220("cipher type: substitution cipher\n");
		if (e)
			cse220("cipher operation: encryption\n");
		else if (d)
			cse220("cipher operation: decryption\n");
		printf("%s", ciphertext);
	} else
	{
		cse220("output file: %s\n", output);
		cse220("cipher type: substitution cipher\n");
		if (e)
			cse220("cipher operation: encryption\n");
		else if (d)
			cse220("cipher operation: decryption\n");
		writeFile(output, ciphertext);
	}
}

void upperCasify(char *text)
{
	int length = strlen(text);
	int i;
	for (i = 0; i < length; i++)
	{
		char c = toupper((int) *(text + i));
		*(text + i) = c;
	}
}

void shift(int shamt, int e, int d, char *text, char *encryptedText)
{
	int length = strlen(text);
	int i;

	for (i = 0; i < length; i++)
	{
		char c = *(text + i);
		if (e)	/* Encrypt */
		{
			if (((c + shamt) > 'Z') &&
				(isupper((int) c)))
			{
				int n = ((('Z' - (c + shamt)) * -1) - 1) % ALPHABET_SIZE;
				c = 65 + n;
			} else if (isupper((int) c))
			{
				c += shamt;
			}
		} else if (d)	/* Decrypt */
		{
			if (((c - shamt) < 'A') &&
				(isupper((int) c)))
			{
				int n = ((('A' - (c - shamt)) * -1) + 1) % ALPHABET_SIZE;
				c = 90 + n;
			} else if (isupper((int) c))
			{
				c -= shamt;
			}
		}
		*(encryptedText + i) = c;
	}
}

void readFile(char *fileName, char *text)
{
	FILE *fp;
	if ((fp = fopen(fileName, "r")) != NULL)
	{
		fscanf(fp, "%[^\n]s", text);
		fclose(fp);
	} else
	{
		exit(EXIT_FAILURE);
	}
}

void writeFile(char *fileName, char *text)
{
	FILE *fp;
	if ((fp = fopen(fileName, "w")) != NULL)
	{
		fprintf(fp, "%s", text);
		fclose(fp);
	} else
	{
		exit(EXIT_FAILURE);
	}
}

void autokey(int n, char **argv, int e, int d)
{
	cse220("initial shift amount: %d\n", n);
	char *input = *(argv + optind + 1);
	char *keyString = *(argv + optind + 2);
	char *output = *(argv + optind + 3);
	
	/* 	If the input file is '-' take input from stdin,
		otherwise take input from the file		*/
	if (*input == '-' && strlen(input) == 1)
	{
		cse220("input file: STD_IN\n");
		printf("Enter input: ");
		scanf("%[^\n]s", plaintext);
	} else
	{
		cse220("input file: %s\n", input);
		readFile(input, plaintext);
	}
	upperCasify(plaintext);
	
	/* Put the key into the buffer */
	if (*keyString == '-' && strlen(keyString) == 1)
	{
		printf("Enter key: ");
		scanf("%[^\n]s", buffer);
	} else
	{
		readFile(keyString, buffer);
	}
	upperCasify(buffer);
	
	createKey();
	createAlphabet();
	constructTabulaRecta(n, e, d);
	cipher(e, d, plaintext, key, ciphertext);
	
	if (*output == '-' && strlen(output) == 1)
	{
		cse220("output file: STD_OUT\n");
		cse220("cipher type: autokey cipher\n");
		if (e)
			cse220("cipher operation: encryption\n");
		else if (d)
			cse220("cipher operation: decryption\n");
		cse220("Tabula Recta\n");
		printTabulaRecta();
		printf("%s", ciphertext);
	} else
	{
		cse220("output file: %s\n", output);
		cse220("cipher type: autokey cipher\n");
		if (e)
			cse220("cipher operation: encryption\n");
		else if (d)
			cse220("cipher operation: decryption\n");
		cse220("Tabula Recta\n");
		printTabulaRecta();
		writeFile(output, ciphertext);
	}
}

void createKey()
{
	int lengthText = strlen(plaintext);
	int lengthBuffer = strlen(buffer);
	int b = 0, pt = 0;
	
	/* Space out the key to match the plaintext spaces */
	while (b < lengthBuffer)
	{
		char c = *(plaintext + pt);
		if (!isupper((int) c))
		{
			*(key + pt) = c;
		} else
		{
			*(key + pt) = *(buffer + b);
			b++;
		}
		pt++;
	}
	
	b = 0; /* Reset buffer counter */
	
	/* Add the rest of the plaintext into the key, skipping spaces */
	while (pt < lengthText)
	{
		char c = *(plaintext + b);
		if ((c == ' ' || !isupper((int) c)) && b >= pt)
		{
			*(key + pt) = c;
		} else if (isupper((int) c))
		{
			*(key + pt) = c;
			pt++;
		}
		b++;
	}
}

void createAlphabet()
{
	int i;
	for (i = 0; i < ALPHABET_SIZE; i++)
	{
		*(alphabet + i) = 'A' + i;
	}
}

void constructTabulaRecta(int shamt, int e, int d)
{
	int i;
	for (i = 0; i < ALPHABET_SIZE; i++)
	{
		shift(shamt + i, 1, 0, alphabet, *(tabula + i));
		/* printf("%s\n", *(tabula + i)); */
	}
}

void printTabulaRecta()
{	
	int i, j;
	cse220PrintChar('\n');
	for (i = 0; i < ALPHABET_SIZE; i++)
	{
		for (j = 0; j < ALPHABET_SIZE; j++)
		{
			cse220PrintChar(*(*(tabula + i) + j));
			if (j != ALPHABET_SIZE - 1)
				cse220PrintChar(' ');
		}
		cse220PrintChar('\n');
	}
	cse220PrintChar('\n');
}

void cipher(int e, int d, char *text, char *k, char *encryptedText)
{
	int length = strlen(text);
	int i, n, m;
	
	/* Encrypt */
	if (e)
	{
		for (i = 0; i < length; i++)
		{
			char textChar = *(text + i);
			char keyChar = *(k + i);
			if (isupper((int) textChar) && isupper((int) keyChar))
			{
				for (n = 0; n < ALPHABET_SIZE; n++) /* Row */
				{
					char rowChar = *(*(tabula) + n);
					if (textChar == rowChar)
					{
						break;
					}
				}
				
				for (m = 0; m < ALPHABET_SIZE; m++)
				{
					char colChar = *(*(tabula + m));
					if (keyChar == colChar)
					{
						break;
					}
				}
				
				char encryptedChar = *(*(tabula + n) + m);
				*(encryptedText + i) = encryptedChar;
			} else
			{
				*(encryptedText + i) = textChar;
			}
		}
	} 
	/* Decrypt */
	else if (d)
	{
		int lengthBuffer = strlen(buffer);
		i = 0; 
		int count = 0;
		while (count < lengthBuffer)
		{
			char ciphertextChar = *(text + i);
			char keyChar = *(k + i);
			if (isupper((int) ciphertextChar) && isupper((int) keyChar))
			{
				for (n = 0; n < ALPHABET_SIZE; n++)
				{
					char colChar = *(*(tabula + n));
					if (keyChar == colChar)
					{
						break;
					}
				}
				
				for (m = 0; m < ALPHABET_SIZE; m++)
				{
					char rowChar = *(*(tabula + n) + m);
					if (ciphertextChar == rowChar)
					{
						break;
					}
				}
				
				char decryptedChar = *(*(tabula) + m);
				*(encryptedText + i) = decryptedChar;
				count++;
			} else
			{
				*(encryptedText + i) = ciphertextChar;
			}
			i++;
		}
		
		/* Time to add the decrypted text from the beginning to the key
			until max length have been reached*/
		count = 0;
		/* Save the index where we were decrypting */
		n = i;
		
		/* Add the rest of the decrypted text into the key, skipping spaces */
		while (i < length)
		{
			char c = *(encryptedText + count);
			if (((c == ' ' || !isupper((int) c)) && count >= i))
			{
				*(k + i) = c;
				*(encryptedText + i) = *(k + i);
			} else if (isupper((int) c))
			{
				/* Change the key value at the index to first char
					in the decryptedText */
				*(k + i) = c;
				
				/* Decrypt the new key with the text */
				char ciphertextChar = *(text + i);
				char keyChar = *(k + i);
				if (isupper((int) ciphertextChar) && isupper((int) keyChar))
				{
					for (n = 0; n < ALPHABET_SIZE; n++)
					{
						char colChar = *(*(tabula + n));
						if (keyChar == colChar)
						{
							break;
						}
					}
					
					for (m = 0; m < ALPHABET_SIZE; m++)
					{
						char rowChar = *(*(tabula + n) + m);
						if (ciphertextChar == rowChar)
						{
							break;
						}
					}
					
					char decryptedChar = *(*(tabula) + m);
					*(encryptedText + i) = decryptedChar;
				} else
				{
					*(encryptedText + i) = ciphertextChar;
				}
				i++;
			}
			count++;
		}
	}
}

void printHeader()
{
	printf("usage: ./a.out [-s | -a | -h]\n");
	
	printf("    -s\t\tSubstitution cipher\n");
	printf("\t\tAdditional parameters: [-e | -d] n INPUT_FILE OUTPUT_FILE\n");
	printf("\t\t    -e\t\t Encrypt using the substitution cipher.\n");
	printf("\t\t    -d\t\t Decrypt using the substitution cipher.\n");
	printf("\t\t     n\t\t The amount of position to shift by.\n");
	printf("\t\t     INPUT_FILE\t This can be any file on the file system or -\n\t\t\t\t which specifies stdin.\n");
	printf("\t\t     OUTPUT_FILE This can be any file on the file system or -\n\t\t\t\t which specifies stdout.\n\n");
	
	printf("    -a\t\tAutokey cipher\n");
	printf("\t\tAdditional parameters: [-e | -d] n INPUT_FILE KEY_FILE OUTPUT_FILE\n");
	printf("\t\t    -e\t\t Encrypt using the autokey cipher.\n");
	printf("\t\t    -d\t\t Decrypt using the autokey cipher.\n");
	printf("\t\t     n\t\t The amount of position to shift by.\n");
	printf("\t\t     INPUT_FILE\t This can be any file on the file system or -\n\t\t\t\t which specifies stdin.\n");
	printf("\t\t     KEY_FILE\t This can be any file on the file system or -\n\t\t\t\t which specifies stdin.\n");
	printf("\t\t     OUTPUT_FILE This can be any file on the file system or -\n\t\t\t\t which specifies stdout.\n\n");
	
	printf("    -h\t\tDisplay this help menu.");
}