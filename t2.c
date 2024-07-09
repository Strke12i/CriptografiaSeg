#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>


# define KEYSIZE 40
/*
    Trabalho 1 - Criptografia para segurança de dados
    Alunos: 
    Antonio Sergio Tolio Rodrigues
    Felipe Colpo Bagesteiro
    Lucas Caetano
*/

char* encodeBase64(const char* input, size_t input_length) {
    const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* output = (char*)malloc(output_length + 1);
    if (output == NULL) {
        return NULL;
    }
    size_t i, j;
    for ( i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? input[i++] : 0;
        uint32_t octet_b = i < input_length ? input[i++] : 0;
        uint32_t octet_c = i < input_length ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[j++] = base64chars[(triple >> 18) & 0x3F];
        output[j++] = base64chars[(triple >> 12) & 0x3F];
        output[j++] = base64chars[(triple >> 6) & 0x3F];
        output[j++] = base64chars[triple & 0x3F];
    }

    for ( i = 0; i < (3 - input_length % 3) % 3; i++) {
        output[output_length - 1 - i] = '=';
    }

    output[output_length] = '\0';
    return output;
}


unsigned char* decodeBase64(const char* input, size_t* output_length) {
    const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_length = strlen(input);
    
    if (input_length % 4 != 0) {
        return NULL;
    }

    *output_length = input_length / 4 * 3;
    if (input[input_length - 1] == '=') (*output_length)--;
    if (input[input_length - 2] == '=') (*output_length)--;

    unsigned char* output = (unsigned char*)malloc(*output_length); 
    if (output == NULL) {
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : strchr(base64chars, input[i++]) - base64chars;
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : strchr(base64chars, input[i++]) - base64chars;
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : strchr(base64chars, input[i++]) - base64chars;
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : strchr(base64chars, input[i++]) - base64chars;

        uint32_t triple = (sextet_a << 3 * 6)
                        + (sextet_b << 2 * 6)
                        + (sextet_c << 1 * 6)
                        + (sextet_d << 0 * 6);

        if (j < *output_length) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) output[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return output;
}

unsigned char* bytesToHex(const unsigned char* bytes, size_t length) {
    const char hexchars[] = "0123456789abcdef";
    unsigned char* hexstring = (unsigned char*)malloc(length * 2 + 1);

    size_t i;
    for ( i = 0; i < length; i++) {
        hexstring[i * 2] = hexchars[(bytes[i] >> 4) & 0xF];
        hexstring[i * 2 + 1] = hexchars[bytes[i] & 0xF];
    }
    hexstring[length * 2] = '\0';
    return hexstring;
}

unsigned char* hexToBytes(const char* hexstring, size_t* output_length) {
    size_t length = strlen(hexstring);
    if (length % 2 != 0) {
        return NULL;
    }

    *output_length = length / 2;
    unsigned char* bytes = (unsigned char*)malloc(*output_length);
    if (bytes == NULL) {
        return NULL;
    }

    size_t i;
    for ( i = 0; i < *output_length; i++) {
        sscanf(hexstring + 2 * i, "%2hhx", &bytes[i]);
    }
    return bytes;
}

unsigned char* xor(const unsigned char* input1, const unsigned char* input2, size_t length) {
    unsigned char* output = (unsigned char*)malloc(length);
    if (output == NULL) {
        return NULL;
    }

    size_t i;
    for ( i = 0; i < length; i++) {
        output[i] = input1[i] ^ input2[i];
    }
    return output;
}

char** decryptXOR(unsigned char* ciphertext, size_t length) {
    char *alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t alphabetLength = 26 * 2;

    char** plaintexts = (char**)malloc(alphabetLength * sizeof(char*));
    if (plaintexts == NULL) {
        return NULL;
    }

    size_t i;
    for ( i = 0; i < alphabetLength; i++) {
        unsigned char key = alphabet[i];
        plaintexts[i] = (char*)malloc(length + 1);
        size_t j;
        for(j =0; j < length; j++) {
            plaintexts[i][j] = ciphertext[j] ^ key;
        }
        plaintexts[i][length] = '\0';
    }
    return plaintexts;
}

char frequencyAnalysis(char** plaintexts, size_t length) {
    char* alphabet = "abcdefghijklmnopqrstuvwxyz";
    float frequency[26] = {12.63, 1.04, 3.88, 9.99, 12.57, 4.02, 1.30, 1.28, 6.18, 0.40, 0.02, 2.78, 4.74, 5.05, 10.73, 2.52, 1.20, 6.53, 7.81, 4.34, 4.63, 5.67, 0.01, 0.21, 0.01, 0.47};

    float bestScore = 0;
    char bestKey = 'a';
    size_t i;
    for ( i = 0; i <26; i++) {
        float score = 0;
        size_t j;
        for ( j = 0; j < length; j++) {
            if(isalpha(plaintexts[i][j])) {
                score += frequency[tolower(plaintexts[i][j]) - 'a'];
            }
        }
        if (score > bestScore) {
            bestScore = score;
            bestKey = alphabet[i];
        }
    }
    return bestKey;

}

int hammingDistance(const unsigned char* input1, const unsigned char* input2, size_t length) {
    int distance = 0;
    size_t i;
    for ( i = 0; i < length; i++) {
        unsigned char x = input1[i] ^ input2[i];
        while (x) {
            distance += x & 1;
            x >>= 1;
        }
    }
    return distance;
}

unsigned char* unsignedChar(const char* input){
    size_t length = strlen(input);
    unsigned char* output = (unsigned char*)malloc(length);
    if (output == NULL) {
        return NULL;
    }
    size_t i;
    for ( i = 0; i < length; i++) {
        output[i] = input[i];
    }
    return output;
}

int *findNNumbersOfMinValues(float* array, size_t length, int n) {
    int* indexes = (int*)malloc(sizeof(int) * n);
    if (indexes == NULL) {
        return NULL;
    }

    size_t i;
    for ( i = 0; i < n; i++) {
        float min = array[0];
        int minIndex = 0;
        size_t j;
        for ( j = 1; j < length; j++) {
            if (array[j] < min) {
                min = array[j];
                minIndex = j;
            }
        }
        indexes[i] = minIndex + 2;
        array[minIndex] = 1000000.0;
    }
    return indexes;
}

int* findBestsKeySize(unsigned char* ciphertext, size_t length) {
    float *allDistances = (float*)malloc(sizeof(float) * KEYSIZE - 1);

    int numBlocks = length / KEYSIZE;
    if(numBlocks < 1) {
        return NULL;
    }

    size_t i;
    for ( i = 2; i <= KEYSIZE; i++) {
        float* distances = (float*)malloc(sizeof(float) * numBlocks);
        if (distances == NULL) {
            return NULL;
        }

        size_t j;
        for ( j = 0; j < numBlocks; j++) {
            distances[j] = hammingDistance(ciphertext + j * KEYSIZE, ciphertext + (j + 1) * KEYSIZE, i);
        }

        float distance = 0.0;
        for ( j = 0; j < numBlocks; j++) {
            distance += distances[j] / i;
        }

        distance /= numBlocks;
        allDistances[i - 2] = distance;
        free(distances);
    }

    int* indexes = findNNumbersOfMinValues(allDistances, KEYSIZE - 2, 5);

    return indexes;
}

char** tranposeBlocks(unsigned char* ciphertext, size_t length, int keySize) {
    char** blocks = (char**)malloc(keySize * sizeof(char*));
    size_t i;
    for(i = 0; i < keySize; i++) {
        blocks[i] = (char*)malloc(keySize + 1);
        size_t j;
        for(j = 0; j < keySize; j++) {
            blocks[i][j] = ciphertext[j * keySize + i];
        }
    }
    return blocks;
}

char* bestkey(char** blocks, size_t length) {
    char* key = (char*)malloc(length + 1);
    if (key == NULL) {
        return NULL;
    }

    size_t i;
    for(i = 0; i < length; i++) {
        char** plaintexts = decryptXOR(unsignedChar(blocks[i]), length);
        key[i] = frequencyAnalysis(plaintexts, length);
    }
    key[length] = '\0';
    return key;
}

void decipherXor(unsigned char* ciphertext, size_t length, char* key, int keyLength) {
    unsigned char* plaintext = (unsigned char*)malloc(length * sizeof(unsigned char));
    size_t i;
    for ( i = 0; i < length; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % keyLength];
    }
    printf("%s\n", plaintext);
}

int main(int argc, char** argv) {
    char* inputBase64 = "FBM9JCMjIT48IjIpMAA2KTA0MiExIwAsOzIyADQ0OiwzKTosJTQ6IDAvISwgKDo7MDQgJDEnNygzIzcoJyc/LicvMik0KDwkOzI2PzwpISs6NDIpMDM+LDYnIyQhJz8vJycgJDkjOj80AyA+MCAyOTo0Nj0nIyAoOzI8OCArPiwnJTwkODY8PyEnPTkwKDw9JykwKCY1PCkwLz05MDQ6IicvKSw2JzwpOiM9PjwoPDg7LyUoJzU6OTQ0OiIlMzEhPCU8IzoEISwmLz8oNik9OScvMTg8MyMsJyc8HzwpFD80KDcoMSkAODkyPD87JyE+MCkjPzwrNiQnKRY+ISc3IjEnFSgxIyEsNic8LDYpPTk0NDAiOCImLCYzPSQjIyE+PCIyKTA1NSgxIyEsPDUWPiEnICgxLzIpNCM+HjQoJywYJyEkNBQ6IhI0MiMxIzciBjM/DycnICQ5JDIkJzQ8DjQrPC88KDIOPCIyKTATPSQjIyE+PDIyPzwnAz86IDY+JikhBzo1NgA0NDosOyk3LAcpMCU0ADohPSk8IzEjMi46KCcoNiMyIDQvPD8lJyE5MCI2PiAnICwhLyUkMSc3KCYnMCwxIz4kNicgKDQiPiQ7LyA5JycnJCMnIB06NSA4PCc6IzEnJz8wNTAsODY6Kzo0MikwNTYpMDM+KDgAISgxIyEkNikEKCYyIyU0KjYjICs2IAUnPyAwLyEsMScgADw1ICIwNTYiIDIhIjArECw2LjwoPDQyKToVJiEUKjYgMSkgLjQrIyQ0Jyc4NCo2PiE0JjkgNDIoNik+PTo1JywlKSEpOjw2GDsvNywxIyAYOy8lKCc1Ojk0NDosJgU2IyE0PCkwByE5MDU2ATAyISwmBTYjITQ8KTAFOig7JTosJggyOSA0MiQmIxY1NDIyPhYjPTknKTcoFi82IzYvMj4HMyEsPDUQKDsyISIxIxAkMCgwJDQ1NywGJyYpMAU2IyE0PCkwBTooOyU6LCYVPC48Jzo+MA4mIDQoMj4WIz05Jyk3KBAiJi40JTIiFiM9OScpNygQIiYuNCUyIhMvICQ2JzYJMDUjIicyPD4WKT8oMi88HToqOjkwJT0kNikQKDsyISIxIwcoNig8ITohOiwWKT8oMi88GTAlPSQ2KRojMTMgOScvMiExIwAsOzIyADQ0OiwQNSMsNikeODkyOik8NTAkJSo6IzQ0NywAAAAAMCsAJDkwNiQnJx4sJzI6IyYTPSQxJzcoMSMWKSAlMi40KRojMyc9OTwqGj0wBz4sJyM/IhspNiMmLz0iJTQ2PjAoMCQ0KjwrMDQ2LjAlNiMhKTY5Jy89OTQjJiA2MyE+OjU3KDI0MikgJzAsOjU2IzEpPCMvIzA4JzU8PiYzIygnLzw/MDU3KCEjMCM6KjwqPCcnPzwoJywwNTY5MCI2ITwlNiM2LzI5IDQyPTkjPSwwKTo5MCgnLDAyISgmIjYvNCU7LCcjPywxKRIhMCs3JCY1PCw8KCA5PDImJDYnPCIzIyE5NCU2IyEpNj4wLyAuIDQgIiYiNj06NTQ/NCImLDYnPD4wKDciITQ6IyEnNjwgJyc/OiI2KTozJyInJzciNi89PCAjPTk0Iz0iIyM3KDgjIDknJzciMSkpKDEjNj4lIzAkNCo6NzQlMiIwMz49Jyk0PzQrMikwNjw+MSkmOTo0Mik6CDIoMTMwLDYnPC80NTouNCMnKDYoOi40NTIiIy89OTAjIjg0MiEiNjMhPjo1Jyg2KDouOjUjIiYrNik8KSA8ICcnPzoyNi47LzAiJjYyPzQjPT48KDwgMCI6IiArMDgnNTwpMCM9PjwoPCAwIjoiMDM+LiA0ICIxIzYpICUyLjQpOiMzJz05PCocLjo0IyIxLyAuMCgnKDAlPCMmMjo5IC83IjEjMj0nKSskOCc3LDgjPTkwMiEkOzIyIDwqNj4hMzcsOzI2PiYjPSk6MDojISM2PjAyNiA8Kj0sOCk3LDkvNywxIyM/MDU2IzYvMiEwMiEoJis6ITsnPiIxJz8kMSc3KDEjNiMmLz0iNCI6PiEnPS48Jxw8ICc3PzoiNj0wNSAiNCowIjsyMi46KzAoJyUyKTAlOiM2KT4kOTU2PyMvNyInIyAJMDUnKCYiPCQmKzohMCImNzAoJyImNTIiMSkwKDsyNj4wIjwkJis6ITApOjk6JTYjISkgPjQpJyg2KDouOic3IDwoOj4hNDI5PDA8PjArNikgJTIuNCkXIjAhISgmNTwpMDM+LiA0ICIxIzEsNi4yPzAqMik6Iz4OPCM9LjwnNywWKT49IDIyLjQpNigtLzQkMScmIDQ2ISgxLyA9OjU6LjQpNiwlMjopOiMgPTQ0Miw0NDYsNCo2IDEjJiA2KT0nICgnIjEjMCI4NjY5MCgwJDQ1Oyw3Lz8kMSc3KCYjMjk8MiYpMDUyPjA0NiA0IiI4PDQ6KTQ1NzgnJz05MCchKDQqOjc0JTIiMSkwOCc1PB06NDcoMy89JDYnPCIXJzAlNDQ2ITArECQwKDAkNCIyDjorIzghJzAsOiI2OzA1Nj8gKyM/OiA6PiYvPCM0KiI4NCo6KzwlMik6NjI/NCcjKCY3JiQmJzYpMDU2IyMpPzs8KzYjISk9LDQ0NiwxIzAiODYmOTQlMiIlJyEsOjYhIj8jJyIwJTwjJjIhODYnPCkwLjI/MTEyPzAjICIzMiQsJyMxLCYvMCIwMjIgNyM+PTQ0MiIgNTwpMDU6PiEjPiwmJTwgJTMnLDEpISQvJzciJiM+IiAyISwmJyEoNDU3LDQyOjs8IjIpMC4mIDQoMiwzLz4pMDA6LDcvPyQvJyEiICcmIDAoJywnJyM/OiImOTwwOik0IjYoNDcmLDkvNywxIzcoISk3IiYpIDk8Njw+MSMjPzolNik8KzYjISkgAzQTFR4YMjwpOiM0PzA1ICIxIyUoJiMhODg2ISIzLyA+PCk9LDklPCAxKT4kOy88KDYnIyw2LzcsMSMjLCcnJz80JDIhPSchIzQnISg0IjIOOisjOCEnMCw6IjY+MCglIjkwNiMxKSM/Oiw2OTo1Nyg2KT49IDIyKTo0Nj4wNTo+ISM+LCYiNi46KyM4IScwLDo2ISIyNDIgNDU2Pjw1Jyg4JyApMC89Kzo0Piw2JzwsISM9OTonPC40NDI5MDQ2LjoqPCo8JTw+OiU6LDkjNjk8JTwoJDM2KC0jIS40NSYsJicnJCMvNywxIyAjNDU8LjwjNywxIzAiODQ2PiUpPT40JDohPCIyKTAJESw2LjI/MCo2IAYvIDkwKzI+MSMaIzMpISA0JTIiMCkjPzogOj4mLzwjNCoiODAzICw2KT0uMC8nIiYjJyg2KDouNDU3KDwoNSInKzI5PCUyKCEjPD88JzcoJi8gOTArMj4lJyEsNik9OScvMTg8ND0sJik/ODYnPCkwNiEiNyo2IDQ1NyghNDI5NCs2IyEpNyw8KDUiJysyLjQpPSwmKSEqNCg6NzQlPCgmNjw/OCM6IjEnMCI7NSc/ICUyIjEjPiIxIz8iJiI2LCAyPCA0JTIiNikhPTo0Mjk8MDIIOSM3KCMjJygnIyA9PDQ6OTojPj0nIzYjMSM3Iic3Jig5LjY9MDQ+JCEnMCI7JTYvMDQwPzwnISg2KT0uJyMnJC8nIT0nKTkoISkgKTAyISwhJz4oOzI8KTQvPSs6ND4sNic8LjooIC48Iz05MCIyPiAnNTg7JTIiOycgIjYvNik0IjYoMSMyLjo0NyI2KT47NCo8PzA1Njk8JTw+ESk2KicjID46IjY4OCUmPyYpNyg3JzAlNDQ2ITQiPCg4FTo+ISM+LCYiNgQ7IDw/OCcwLDojNjU8ITopNDM+LCU0Nik8NSMiJi8wLDojMj0hLzciMDUjLCcnMiwnIzIsOSM+KTAzPi46KDk4OzI8KTAlPCAlIycoOyU6LCYuMi88KjopNCI2PjAnJyQhMzcoJicgKCcjPiwxNyYkJy83LCYiJj80KCcoNDQ2LDkvKSw2JzwpOiUmPyYpHSgmMjY+MCgnJDEpNj4hIzAsJS8nODkpNygzLz0oOjY2PzMvPz0nKTUkJjU6IjsnPykwNTYnNCI8KTA1MD8wMDYiJjQ2PCAvICQhKSA9Ji8wIjMvICQ2KSA8ICM3KCMjPj4wNCc/NCQyIT0nNyImJzwhOig0IjEpMDgnNTwoJyM/LDYvPCM0JyAuOScgPjA1NyglNDwvOSM+LCY3JighKTciMCEhKCY1PCkwMDYoJjIyPzQ2JyI0NDY+OiolKCc=";
    size_t ciphertext_length = strlen(inputBase64);
    unsigned char* ciphertext = decodeBase64(inputBase64, &ciphertext_length);
    size_t i;
   
    if(ciphertext == NULL) {
        return 1;
    }

    int *bestKeys = findBestsKeySize(ciphertext, ciphertext_length);
    for(i = 0; i < 5; i++) {
        char** blocks = tranposeBlocks(ciphertext, ciphertext_length, bestKeys[i]);
        printf("Key size: %d\n", bestKeys[i]);
        char *key = bestkey(blocks, bestKeys[i]);
        decipherXor(ciphertext, ciphertext_length, key, bestKeys[i]);
    }



    


    return 0;
}
