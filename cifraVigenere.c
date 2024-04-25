#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
    Membros do Grupo:
    - Antonio Sergio Rodrigues Tolio
    - Felipe Colpo Bagesteiro
    - Lucas Caetano

*/


void vigenere(char *chave, char *plainText, char* cipherText){
    size_t lenPlainText = strlen(plainText);
    size_t lenChave = strlen(chave);
    
    size_t i;
    for (i = 0; i < lenPlainText; i++)
    {
        if(isalpha(plainText[i])){
            char c = toupper(plainText[i]);
            char k = toupper(chave[i % lenChave]);
            int offset = 'A';

            cipherText[i] = (c + k - (2 * offset)) % 26 + offset;
        }else{
            cipherText[i] = plainText[i];
        }
    }
}

int main(int argc, char *argv[])
{
    char *plainText;
    char *chave;
    char *cipherText;

    if(argc < 3){
        fprintf(stderr,"Uso: %s <texto> <chave>\n", argv[0]);
        return 1;
    }

    plainText = argv[1];
    chave = argv[2];
    
    size_t lenPlainText = strlen(plainText);
    cipherText = (char*)malloc(sizeof(char) * lenPlainText);

    if(strlen(chave) == 0){
        fprintf(stderr,"Chave vazia\n");
        return 1;
    }

    vigenere(chave, plainText, cipherText);
    fprintf(stdout,"Texto cifrado: %s\n", cipherText);
    
    free(cipherText);

    return 0;
}
