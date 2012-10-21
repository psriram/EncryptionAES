//
//  main.m
//  EncryptionAES
//
//  Created by Preethi Srinivasan on 9/14/12.
//  Copyright (c) 2012 Preethi Srinivasan. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>


char * encryptAesCbc(char *, const char *);
NSData * encryptDecryptAES();
NSData * encryptDES(NSString *);
NSString* Base64Encode (NSData *data);
char * encryptedString;

int main(int argc, const char * argv[])
{

    @autoreleasepool {
        
        NSData *data = encryptDecryptAES();
     
        /*NSData *data = encryptDecryptAES();
        NSString *b64EncStr = Base64Encode(data);
        NSLog(@"Base 64 encoded = %@",b64EncStr);
        
               
        unichar* hexChars = (unichar*)malloc(sizeof(unichar) * (data.length*2));
        unsigned char* bytes = (unsigned char*)data.bytes;
        for (NSUInteger i = 0; i < data.length; i++) {
            unichar c = bytes[i] / 16;
            if (c < 10) c += '0';
            else c += 'a' - 10;
            hexChars[i*2] = c;
            c = bytes[i] % 16;
            if (c < 10) c += '0';
            else c += 'a' - 10;
            hexChars[i*2+1] = c;
        }
        NSString* retVal = [[NSString alloc] initWithCharactersNoCopy:hexChars
                                                               length:data.length*2
                                                         freeWhenDone:YES];
        NSLog(@"Encrypted HexString : %@",retVal);*/
        
    } 
    return 0;
}


NSData * encryptDecryptAES()
{
  	int i;
	//size_t numBytesEncrypted = 0;
   // NSString *key =@"f3054d8b7471284bdb4ee18afc3b091b";
    NSString *key = @"a16byteslongkey!a16byteslongkey!";
       
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero( keyPtr, sizeof(keyPtr) ); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    char *dataIn = "Data to encrypt";
  //  char *dataIn = "iphone";

  // char *dataIn = "Data to encrypt";
    
    
    
    char dataOut[500];// set it acc ur data
    char dataOut2[500];
    bzero(dataOut, sizeof(dataOut));
    size_t numBytesEncrypted = 0;
    
    //encrypt
    CCCryptorStatus result = CCCrypt(kCCEncrypt, kCCAlgorithmAES128,kCCOptionPKCS7Padding,  keyPtr,kCCKeySizeAES256, NULL, dataIn, strlen(dataIn), dataOut, sizeof(dataOut), &numBytesEncrypted);
    
    NSData *data_enc = [NSData dataWithBytesNoCopy:dataOut length:numBytesEncrypted];
    NSString *b64EncStr1 = Base64Encode(data_enc);
    NSLog(@"Base 64 encoded = %@",b64EncStr1);
    
    /*printf("successfully encrypted %ld bytes\n", numBytesEncrypted);
    for(i=0;i<numBytesEncrypted;++i)
        printf("%02x", (unsigned int) dataOut[i]);
    
    printf("\n");*/
   
    if (result == kCCSuccess) {
		//decrypt data
        bzero(dataOut2, sizeof(dataOut2));
        size_t numBytesDecrypted = 0;
        CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,kCCOptionPKCS7Padding, keyPtr,kCCKeySizeAES256, NULL, dataOut, numBytesEncrypted, dataOut2, sizeof(dataOut2), &numBytesDecrypted);
        
        if (result == kCCSuccess) {
            //the returned NSData takes ownership of the buffer and will free it on deallocation
            return [NSData dataWithBytesNoCopy:dataOut length:numBytesEncrypted];
        }

	}
	
	free(dataOut); //free the buffer;
    free(dataOut2); //free the buffer;
	return nil;
}

NSString* Base64Encode (NSData *data){
    //Point to start of the data and set buffer sizes
    int inLength = [data length];
    int outLength = ((((inLength * 4)/3)/4)*4) + (((inLength * 4)/3)%4 ? 4 : 0);
    const char *inputBuffer = [data bytes];
    char *outputBuffer = malloc(outLength);
    outputBuffer[outLength] = 0;
    
    //64 digit code
    static char Encode[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    //start the count
    int cycle = 0;
    int inpos = 0;
    int outpos = 0;
    char temp;
    
    //Pad the last to bytes, the outbuffer must always be a multiple of 4
    outputBuffer[outLength-1] = '=';
    outputBuffer[outLength-2] = '=';
    
   
    
    
    while (inpos < inLength){
        switch (cycle) {
            case 0:
                outputBuffer[outpos++] = Encode[(inputBuffer[inpos]&0xFC)>>2];
                cycle = 1;
                break;
            case 1:
                temp = (inputBuffer[inpos++]&0x03)<<4;
                outputBuffer[outpos] = Encode[temp];
                cycle = 2;
                break;
            case 2:
                outputBuffer[outpos++] = Encode[temp|(inputBuffer[inpos]&0xF0)>> 4];
                temp = (inputBuffer[inpos++]&0x0F)<<2;
                outputBuffer[outpos] = Encode[temp];
                cycle = 3;
                break;
            case 3:
                outputBuffer[outpos++] = Encode[temp|(inputBuffer[inpos]&0xC0)>>6];
                cycle = 4;
                break;
            case 4:
                outputBuffer[outpos++] = Encode[inputBuffer[inpos++]&0x3f];
                cycle = 0;
                break;                          
            default:
                cycle = 0;
                break;
        }
    }
    NSString *pictemp = [NSString stringWithUTF8String:outputBuffer];
    free(outputBuffer); 
    return pictemp;
}
