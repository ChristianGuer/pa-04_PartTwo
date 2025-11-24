/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

Written By: 
     1- Ash Rauch
	 2- Christian Guerrero
Submitted on: 
    11/23/25
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{

    
    
    // Your code from pa-04_PartOne
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by STUDENTS_LAST_NAMES" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor
    

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;   

    if ( getKeyFromFile( "basim/basimKey.bin" , &Kb ) == 0 ) {
        fprintf( stderr , "\nCould not get Basim's Master key & IV.\n" ) ;
        fprintf( log ,    "\nCould not get Basim's Master key & IV.\n" ) ;
        fclose(log); exit(-1);
    }
    fprintf( log , "Basim has this Master Kb { key , IV }\n" );
    BIO_dump_indent_fp( log , (const char*)Kb.key , SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
	BIO_dump_indent_fp( log , (const char*)Kb.iv  , INITVECTOR_LEN   , 4 );
    fprintf( log , "\n" );


    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  

	getNonce4Basim(1, Nb);
    fprintf( log , "Basim will use this Nonce:  Nb\n"  ) ;
	BIO_dump_indent_fp( log , (const char*)Nb , NONCELEN , 4 );
    fprintf( log , "\n" );

    fflush( log ) ;
    
    
    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;
    myKey_t  Ks ;      // out: session key Ks
    char    *IDa ;     // out: dynamically allocated IDa string
    Nonce_t   Na2 ;    // out: Na2 echoed back
    MSG3_receive( log, fd_A2B, &Kb, &Ks, &IDa, &Na2);


    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;

    Nonce_t fNa2;
    fNonce( fNa2, Na2 );   // r = n + 1 (big-endian)

    uint8_t *msg4 = NULL;
    size_t LenMsg4 = MSG4_new( log, &msg4, &Ks, &fNa2, &Nb );
    if (LenMsg4 == 0 || msg4 == NULL) {
        fprintf(log, "Basim: MSG4_new failed\n");
        fflush(log);
        fclose(log);
        exitError("Basim: MSG4_new failed");
    }

    /* 1) Send Len(MSG4) first */
    if (write(fd_B2A, &LenMsg4, sizeof(size_t)) != (ssize_t)sizeof(size_t)) {
        fprintf(log,
                "Basim: Unable to send all %lu bytes of Len(MSG4) to Amal ... EXITING\n",
                (unsigned long)sizeof(size_t));
        fflush(log);
        fclose(log);
        exitError("Basim: Unable to send Len(MSG4) to Amal");
    }

    /* 2) Then send the encrypted MSG4 bytes */
    size_t off = 0;
    while (off < LenMsg4) {
        ssize_t n = write(fd_B2A, msg4 + off, LenMsg4 - off);
        if (n <= 0) {
            fprintf(log,
                    "Basim: Unable to send all %lu bytes of MSG4 to Amal ... EXITING\n",
                    (unsigned long)LenMsg4);
            fflush(log);
            fclose(log);
            exitError("Basim: Unable to send MSG4 to Amal");
        }
        off += (size_t)n;
    }

    fprintf(log, "Basim Sent the above MSG4 to Amal\n\n");
    fflush(log);

    // optionally: free(msg4);

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;
    Nonce_t expectedfNb;
    Nonce_t rcvdfNb;
    fNonce( expectedfNb , Nb );   // <-- result first, input second
    
    fprintf( log , "Basim is expecting back this f( Nb ) in MSG5:\n" );
    BIO_dump_indent_fp( log , (const char *)expectedfNb , NONCELEN , 4 );
    fprintf( log , "\n" );

    MSG5_receive( log, fd_A2B, &Ks, &rcvdfNb );

    // Compare byte-for-byte
    if( memcmp( rcvdfNb , expectedfNb , NONCELEN ) == 0 )
    {
        fprintf( log , "Basim received Message 5 from Amal with this f( Nb ): >>>> VALID\n" );
    }
    else
    {
        fprintf( log , "Bsim received Message 5 from Amal with this f( Nb ): >>>> FAILED\n" );
    }
    BIO_dump_indent_fp( log , (const char *)rcvdfNb , NONCELEN , 4 );
    fprintf( log , "\n" );
    fflush( log );

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
