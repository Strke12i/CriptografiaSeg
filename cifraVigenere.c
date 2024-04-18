#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void vigenere(char *chave, char *plainText){
    size_t lenPlainText = strlen(plainText);
    size_t lenChave = strlen(chave);
    char* cipherText = (char*)malloc(sizeof(char) * lenPlainText);

    size_t i;
    for (i = 0; i < lenPlainText; i++)
    {
        if(isalpha(plainText[i])){
            char c = toupper(plainText[i]);
            char k = toupper(chave[i % lenChave]);
            int offset = 'A';

            cipherText[i] = (c - offset + k - offset) % 26 + offset;
        }else{
            cipherText[i] = plainText[i];
        }
    }

    fprintf(stdout,"Texto cifrado: %s\n", cipherText);
    
    free(cipherText);
}

int main(int argc, char *argv[])
{
    char *plainText;
    char *chave;
    if(argc < 3){
        fprintf(stderr,"Uso: %s <texto> <chave>\n", argv[0]);
        return 1;
    }

    plainText = argv[1];
    chave = argv[2];
    

    if(strlen(chave) == 0){
        fprintf(stderr,"Chave vazia\n");
        return 1;
    }

    vigenere(chave, plainText);

    return 0;
}
