package mini_aes;
import java.io.*;
import java.util.Random;

public class aes {
	
    static int[][] sBox = {
			{0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF},
			{0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7}
	};

    static int [][] multiplicationMatrix = {{3,2},{2,3}};

    static int[][] privateKey = new int[2][2];

    
    static int[][] word0  = new int[2][2];
    static int[][] word1  = new int[2][2];
    static int[][] word2  = new int[2][2]; 
    
    static int[][] iv = new int[2][2]; 
    
    static int[][] input_16  = {{0xF,0xA},{0x4,0xD}}; 
    static int[][] output_16 = new int[2][2]; 
    
    static int[][] input_32  = {{0x9,0xC,0x6,0x3},{0x9,0xC,0x6,0x2}}; 
    static int[][] output_32 = new int[2][4];
  
	
	public static void main(String[] args)throws IOException {      
		   try{  
		       MiniAES_32bits();
		       MiniAES_32bits_CBC();
		       
		       Key_observations();
		   }   
		   catch(Exception ex) {
			   System.out.println("Exception thrown : ");
			   ex.printStackTrace();
		   }	
    }
	
	
	public static void MiniAES_16bits() {
		
		// --- Key Generation ---
		randomKeyGeneration();
	    keyExpansion();
	    
		// --- ENCRYPTION ---
		pre_e_MiniAES_16_Data();   // Print DATA(private-key , plain text) , Before encryption
		Encryption_16();
		post_e_MiniAES_16_Data();  // Print DATA(cipher text) , After encryption
		
		// --- DECRYPTION ---
		pre_d_MiniAES_16_Data();   // Print DATA(private-key , cipher text) , Before decryption
		Decryption_16();
		post_d_MiniAES_16_Data();  // Print DATA(plain text) , After decryption

	}
	
	public static void MiniAES_32bits() {
	
		// --- Key Generation ---
		randomKeyGeneration();
	    keyExpansion();
	    
		// --- ENCRYPTION ---
		pre_e_MiniAES_32_Data();   // Print DATA(private-key , plain text) , Before encryption
		Encryption_32();
		post_e_MiniAES_32_Data();  // Print DATA(cipher text) , After encryption
		
		// --- DECRYPTION ---
		pre_d_MiniAES_32_Data();   // Print DATA(private-key , cipher text) , Before decryption
		Decryption_32();
		post_d_MiniAES_32_Data();  // Print DATA(plain text) , After decryption

	}
	
	
	public static void MiniAES_32bits_CBC() {
		
		// --- Key Generation ---
		randomKeyGeneration_CBC();
	    keyExpansion();
	    
		// --- ENCRYPTION ---
		pre_e_MiniAES_CBC_32_Data();   // Print DATA(private-key , plain text) , Before encryption
		Encryption_32_CBC();
		post_e_MiniAES_CBC_32_Data();  // Print DATA(cipher text) , After encryption
		
		// --- DECRYPTION ---
		pre_d_MiniAES_CBC_32_Data();   // Print DATA(private-key , cipher text) , Before decryption
		Decryption_32_CBC();
		post_d_MiniAES_CBC_32_Data();  // Print DATA(plain text) , After decryption

	}
	

	// ******************************************************************************************************* Encryption process functions
	// ******************************************************* 16-bits Encryption 
		public static void Encryption_16() {
			  int[][] processMatrix  = new int[2][2]; 
			  
			     // ROUND 1
				     // STEP 1
					     // Key expansion (done only one time , as keys are generated in one function call)
						 // XOR with round key 0	
						 processMatrix = xorMatrix(input_16,word0);
				     // STEP 2		 
						 // Nibble sub
						 processMatrix = NibbleSub(processMatrix);
				     // STEP 3		 
						 // Shift row
						 processMatrix = shiftRow(processMatrix);
			         // STEP 4			 
						 // Mix column
						 processMatrix = mixColumns(processMatrix,multiplicationMatrix);
					 // STEP 5		 
						 // Key expansion (Round 1)
						 // XOR with round key 1
						 processMatrix = xorMatrix(processMatrix,word1);
				  // ROUND 2 
					 // STEP 1
						 // Nibble sub
					     processMatrix = NibbleSub(processMatrix);     
					 // STEP 2		 
					     // Shift row
						 processMatrix = shiftRow(processMatrix);	 
					 // STEP 3		 
						 // Key expansion (Round 2)
					     // XOR with round key 2
						 processMatrix = xorMatrix(processMatrix,word2);	 
				         output_16 = processMatrix;		          
		  }
	
	
	// ******************************************************* 32-bits Encryption
		public static void Encryption_32() {
			  int[][] processMatrix1  = new int[2][2]; 
			  int[][] processMatrix2  = new int[2][2]; 	  
			  
	  	      // PRE Process
			  // Divide 32-bits input into two 16-bits 
			  int jx=0;
			  for(int i=0;i<2;i++) { 
				 for(int j=0;j<2;j++) {
					 processMatrix1[i][j]=input_32[0][jx];
					 processMatrix2[i][j]=input_32[1][jx];
					 jx+=1;
				 }
			  }
			  
			           
			     // ROUND 1
				     // STEP 1
					     // Key expansion (done only one time , as keys are generated in one function call)
						 // XOR with round key 0	
			             processMatrix1 = xorMatrix(processMatrix1,word0);
			             processMatrix2 = xorMatrix(processMatrix2,word0);
				     // STEP 2		 
						 // Nibble sub
			             processMatrix1 = NibbleSub(processMatrix1);
			             processMatrix2 = NibbleSub(processMatrix2);
				     // STEP 3		 
						 // Shift row
			             processMatrix1 = shiftRow(processMatrix1);
			             processMatrix2 = shiftRow(processMatrix2);
					// STEP 4			 
						 // Mix column
			             processMatrix1 = mixColumns(processMatrix1,multiplicationMatrix);
			             processMatrix2 = mixColumns(processMatrix2,multiplicationMatrix);
							
					 // STEP 5		 
						 // Key expansion (Round 1)
						 // XOR with round key 1
			             processMatrix1 = xorMatrix(processMatrix1,word1);
			             processMatrix2 = xorMatrix(processMatrix2,word1);
				  // ROUND 2 
					 // STEP 1
						 // Nibble sub
			             processMatrix1 = NibbleSub(processMatrix1);
			             processMatrix2 = NibbleSub(processMatrix2);     
					 // STEP 2		 
					     // Shift row
			             processMatrix1 = shiftRow(processMatrix1);
			             processMatrix2 = shiftRow(processMatrix2);	 
					 // STEP 3		 
						 // Key expansion (Round 2)
					     // XOR with round key 2
			             processMatrix1 = xorMatrix(processMatrix1,word2);
			             processMatrix2 = xorMatrix(processMatrix2,word2);	 
			         
			   		            
	         // Post process    
	         // Fusion to 32-bits matrix    
	          int z=0;
	   		  for(int i=0;i<2;i++) { 
	   			 for(int j=0;j<2;j++) {
	   				output_32[0][z]=processMatrix1[i][j];
	   				output_32[1][z]=processMatrix2[i][j];
	   				 z+=1;
	   			 }
	   		  }	          
		 }
		
		public static void Encryption_32_CBC() {
			  int[][] processMatrix1  = new int[2][2]; 
			  int[][] processMatrix2  = new int[2][2]; 	  
			  
	  	      // PRE Process
			  // Divide 32-bits input into two 16-bits 
			  int jx=0;
			  for(int i=0;i<2;i++) { 
				 for(int j=0;j<2;j++) {
					 processMatrix1[i][j]=input_32[0][jx];
					 processMatrix2[i][j]=input_32[1][jx];
					 jx+=1;
				 }
			  }
			  
			  
			          
			  // ROUND 1 CBC
			         // Initialization Vector XORed with Plain-Text 1
			         processMatrix1 = xorMatrix(processMatrix1,iv);
			         
			         // Block Cipher encryption
				     // ROUND 1
					     // STEP 1
						     // Key expansion (done only one time , as keys are generated in one function call)
							 // XOR with round key 0	
				             processMatrix1 = xorMatrix(processMatrix1,word0);
					     // STEP 2		 
							 // Nibble sub
				             processMatrix1 = NibbleSub(processMatrix1);
					     // STEP 3		 
							 // Shift row
				             processMatrix1 = shiftRow(processMatrix1);
				         // STEP 4			 
							 // Mix column
				             processMatrix1 = mixColumns(processMatrix1,multiplicationMatrix);
						 // STEP 5		 
							 // Key expansion (Round 1)
							 // XOR with round key 1
				             processMatrix1 = xorMatrix(processMatrix1,word1);
					  // ROUND 2 
						 // STEP 1
							 // Nibble sub
				             processMatrix1 = NibbleSub(processMatrix1);
						 // STEP 2		 
						     // Shift row
				             processMatrix1 = shiftRow(processMatrix1);
						 // STEP 3		 
							 // Key expansion (Round 2)
						     // XOR with round key 2
				             processMatrix1 = xorMatrix(processMatrix1,word2);
	          // ROUND 2 CBC
			         // Block 1 cipher text XORed with Plain-Text 2
					 processMatrix2 = xorMatrix(processMatrix2,processMatrix1);
					 
			         // Block Cipher encryption
				     // ROUND 1
					     // STEP 1
						     // Key expansion (done only one time , as keys are generated in one function call)
							 // XOR with round key 0	
					         processMatrix2 = xorMatrix(processMatrix2,word0);
					     // STEP 2		 
							 // Nibble sub
					         processMatrix2 = NibbleSub(processMatrix2);
					     // STEP 3		 
							 // Shift row
					         processMatrix2 = shiftRow(processMatrix2);
				         // STEP 4			 
							 // Mix column
					         processMatrix2 = mixColumns(processMatrix2,multiplicationMatrix);
						 // STEP 5		 
							 // Key expansion (Round 1)
							 // XOR with round key 1
					         processMatrix2 = xorMatrix(processMatrix2,word1);
					  // ROUND 2 
						 // STEP 1
							 // Nibble sub
					         processMatrix2 = NibbleSub(processMatrix2);
						 // STEP 2		 
						     // Shift row
					         processMatrix2 = shiftRow(processMatrix2);
						 // STEP 3		 
							 // Key expansion (Round 2)
						     // XOR with round key 2
					         processMatrix2 = xorMatrix(processMatrix2,word2);        
			   		            
	         // Post process    
	         // Fusion to 32-bits matrix    
	          int z=0;
	   		  for(int i=0;i<2;i++) { 
	   			 for(int j=0;j<2;j++) {
	   				output_32[0][z]=processMatrix1[i][j];
	   				output_32[1][z]=processMatrix2[i][j];
	   				 z+=1;
	   			 }
	   		  }	          
		 }
	
	
	
	
	// ******************************************************************************************************* Decryption process functions
	// ******************************************************* 16-bits Decryption 
		public static void Decryption_16() {
			int[][] processMatrix  = new int[2][2]; 
					
			processMatrix = output_16;
			// ROUND 2
			     // STEP 1
				     // XOR with round key 2
				     processMatrix = xorMatrix(processMatrix,word2);	
				     // No need to reverse Key expansion (Round 2)
				 // STEP 2		 
			         // Reverse Shift row
				     processMatrix = shiftRow(processMatrix);
				 // STEP 3
					 // Reverse Nibble sub
				     processMatrix = invNibbleSub_1(processMatrix); 

			// ROUND 1 
				 // STEP 1
				     // XOR with round key 1
				     processMatrix = xorMatrix(processMatrix,word1);	 
				     // No need to reverse Key expansion (Round 1)
				 // STEP 2			 
					 // Reverse Mix column
					 processMatrix = mixColumns(processMatrix,multiplicationMatrix);    
			     // STEP 3		 
					 // Shift row 
					 processMatrix = shiftRow(processMatrix);
			     // STEP 4		 
					 // Reverse Nibble sub
					 processMatrix = invNibbleSub_1(processMatrix);
			     // STEP 5
				     // XOR with round key 0
				     processMatrix = xorMatrix(processMatrix,word0);	 
				     // No need to reverse Key expansion (Round 0)
				     output_16 = processMatrix;	
		}
		
		
	// ******************************************************* 32-bits Decryption
		public static void Decryption_32() {
			int[][] processMatrix1  = new int[2][2]; 
			int[][] processMatrix2  = new int[2][2];  
							
			// PRE Process
			  // Divide 32-bits input into two 16-bits 
			  int jx=0;
			  for(int i=0;i<2;i++) { 
				 for(int j=0;j<2;j++) {
					 processMatrix1[i][j]=output_32[0][jx];
					 processMatrix2[i][j]=output_32[1][jx];
					 jx+=1;
				 }
			  }
			  
			// ROUND 2
			     // STEP 1
				     // XOR with round key 2
			         processMatrix1 = xorMatrix(processMatrix1,word2);	
			         processMatrix2 = xorMatrix(processMatrix2,word2);
				     // No need to reverse Key expansion (Round 2)
				 // STEP 2		 
			         // Reverse Shift row
			         processMatrix1 = shiftRow(processMatrix1);
			         processMatrix2 = shiftRow(processMatrix2);
				 // STEP 3
					 // Reverse Nibble sub
			         processMatrix1 = invNibbleSub_1(processMatrix1); 
			         processMatrix2 = invNibbleSub_1(processMatrix2);

			// ROUND 1 
				 // STEP 1
				     // XOR with round key 1
			         processMatrix1 = xorMatrix(processMatrix1,word1);	
			         processMatrix2 = xorMatrix(processMatrix2,word1);
				     // No need to reverse Key expansion (Round 1)
				 // STEP 2			 
					 // Reverse Mix column
			         processMatrix1 = mixColumns(processMatrix1,multiplicationMatrix);    
			         processMatrix2 = mixColumns(processMatrix2,multiplicationMatrix);  
			     // STEP 3		 
					 // Shift row 
			         processMatrix1 = shiftRow(processMatrix1);
			         processMatrix2 = shiftRow(processMatrix2);
			     // STEP 4		 
					 // Reverse Nibble sub
			         processMatrix1 = invNibbleSub_1(processMatrix1);
			         processMatrix2 = invNibbleSub_1(processMatrix2);
			     // STEP 5
				     // XOR with round key 0
			         processMatrix1 = xorMatrix(processMatrix1,word0);	
			         processMatrix2 = xorMatrix(processMatrix2,word0);	
				     // No need to reverse Key expansion (Round 0)
			         
	     // Post process    
         // Fusion to 32-bits matrix    
          int z=0;
   		  for(int i=0;i<2;i++) { 
   			 for(int j=0;j<2;j++) {
   				output_32[0][z]=processMatrix1[i][j];
   				output_32[1][z]=processMatrix2[i][j];
   				 z+=1;
   			 }
   		  }
		}
		
		public static void Decryption_32_CBC() {
			int[][] processMatrix1  = new int[2][2]; 
			int[][] processMatrix2  = new int[2][2];  
							
			// PRE Process
			  // Divide 32-bits input into two 16-bits 
			  int jx=0;
			  for(int i=0;i<2;i++) { 
				 for(int j=0;j<2;j++) {
					 processMatrix1[i][j]=output_32[0][jx];
					 processMatrix2[i][j]=output_32[1][jx];
					 jx+=1;
				 }
			  }	  
			
			// ROUND 1 CBC
			    // Block cipher decryption
				// ROUND 2
				     // STEP 1
					     // XOR with round key 2
				         processMatrix2 = xorMatrix(processMatrix2,word2);
					     // No need to reverse Key expansion (Round 2)
					 // STEP 2		 
				         // Reverse Shift row
				         processMatrix2 = shiftRow(processMatrix2);
					 // STEP 3
						 // Reverse Nibble sub
				         processMatrix2 = invNibbleSub_1(processMatrix2);
	
				// ROUND 1 
					 // STEP 1
					     // XOR with round key 1
				         processMatrix2 = xorMatrix(processMatrix2,word1);
					     // No need to reverse Key expansion (Round 1)
					 // STEP 2			 
						 // Reverse Mix column
				         processMatrix2 = mixColumns(processMatrix2,multiplicationMatrix);  
				     // STEP 3		 
						 // Shift row 
				         processMatrix2 = shiftRow(processMatrix2);
				     // STEP 4		 
						 // Reverse Nibble sub
				         processMatrix2 = invNibbleSub_1(processMatrix2);
				     // STEP 5
					     // XOR with round key 0
				         processMatrix2 = xorMatrix(processMatrix2,word0);	
				// XOR with previous cipher-text
				processMatrix2 = xorMatrix(processMatrix2,processMatrix1);
				         
	      // ROUND 2 CBC
			    // Block cipher decryption
				// ROUND 2
				     // STEP 1
					     // XOR with round key 2
				         processMatrix1 = xorMatrix(processMatrix1,word2);
					     // No need to reverse Key expansion (Round 2)
					 // STEP 2		 
				         // Reverse Shift row
				         processMatrix1 = shiftRow(processMatrix1);
					 // STEP 3
						 // Reverse Nibble sub
				         processMatrix1 = invNibbleSub_1(processMatrix1);
	
				// ROUND 1 
					 // STEP 1
					     // XOR with round key 1
				         processMatrix1 = xorMatrix(processMatrix1,word1);
					     // No need to reverse Key expansion (Round 1)
					 // STEP 2			 
						 // Reverse Mix column
				         processMatrix1 = mixColumns(processMatrix1,multiplicationMatrix);  
				     // STEP 3		 
						 // Shift row 
				         processMatrix1 = shiftRow(processMatrix1);
				     // STEP 4		 
						 // Reverse Nibble sub
				         processMatrix1 = invNibbleSub_1(processMatrix1);
				     // STEP 5
					     // XOR with round key 0
				         processMatrix1 = xorMatrix(processMatrix1,word0);			
				// Initialization Vector XORed with Plain-Text 1    
				processMatrix1 = xorMatrix(processMatrix1,iv);	

	     // Post process    
         // Fusion to 32-bits matrix    
          int z=0;
   		  for(int i=0;i<2;i++) { 
   			 for(int j=0;j<2;j++) {
   				output_32[0][z]=processMatrix1[i][j];
   				output_32[1][z]=processMatrix2[i][j];
   				 z+=1;
   			 }
   		  }
		}
		 
	
	
	
    // ******************************************************************************************************* Core process functions

	public static void randomKeyGeneration() {
		Random random = new Random();
		for(int i=0;i<2;i++) {
			for(int j=0;j<2;j++) {
				privateKey[i][j] = random.nextInt(16);
			}
		}
	}
	
	public static void randomKeyGeneration_CBC() {
		Random random = new Random();
		for(int i=0;i<2;i++) {
			for(int j=0;j<2;j++) {
				privateKey[i][j] = random.nextInt(16);
				iv[i][j]         = random.nextInt(16);
			}
		}
	}
	
	public static void keyExpansion() {
 	    int rcon1  = 0b0001;
 	    int rcon2  = 0b0010;

    	word0[0][0] = privateKey[0][0];
    	word0[0][1] = privateKey[0][1];
    	word0[1][0] = privateKey[1][0];
    	word0[1][1] = privateKey[1][1];

    	word1[0][0] = word0[0][0] ^ NibbleSub(word0[1][1]) ^ (rcon1);
    	word1[0][1] = word0[0][1] ^ word0[0][0];
    	word1[1][0] = word0[1][0] ^ word0[0][1];
    	word1[1][1] = word0[1][1] ^ word0[1][0];

 	    word2[0][0] = word1[0][0] ^ NibbleSub(word1[1][1]) ^ (rcon2);
 	    word2[0][1] = word1[0][1] ^ word1[0][0];
 	    word2[1][0] = word1[1][0] ^ word1[0][1];
 	    word2[1][1] = word1[1][1] ^ word1[1][0];
	}
	
	public static int[][] NibbleSub(int[][] stateMatrix) {
		int [][] matrix = new int [2][2];
		
		for(int i=0;i<2;i++){
			   for(int j=0;j<2;j++){		   	 
				   for(int ix=0;ix<16;ix++){
				     if(stateMatrix[i][j] == sBox[0][ix]) matrix[i][j] = sBox[1][ix];  		
				   }
			   }
		}
		
		return matrix;
	}
	
	public static int NibbleSub(int n) {
		   for(int i=0;i<15;i++){
			  if(n == sBox[0][i]) return sBox[1][i];  		
		   }
	    return 0;
	} 
	
	public static int[][] invNibbleSub_1(int[][] stateMatrix) {
	 int [][] matrix = new int [2][2];

	 for(int i=0;i<2;i++){
	   for(int j=0;j<2;j++){		   	 
		   for(int ix=0;ix<16;ix++){
		     if(stateMatrix[i][j] == sBox[1][ix]) matrix[i][j] = sBox[0][ix];  		
		   }
	   }
	  }
			 
	  return matrix;	 
	}
	
	public static int[][] shiftRow(int [][] matrix) {
		// first row  : no rotation
	    // second row : rotated by one nibble		
		int x=0;
		for(int i=1;i<2;i++) {
			for(int j=1;j<2;j++) {
			   x = matrix[i][0];
			   matrix[i][0] = matrix[i][1];
			   matrix[i][1] = x;			   
			}
		}
		return matrix;
	}
	
	public static int[][] mixColumns(int [][] stateMatrix, int [][] constantMatrix) {	
		int [][] matrix = new int [2][2];
        
		matrix[0][0]= xorPoly(multiplicationPoly(stateMatrix[0][0],constantMatrix[0][0]) , multiplicationPoly(stateMatrix[1][0],constantMatrix[0][1]));
		matrix[0][1]= xorPoly(multiplicationPoly(stateMatrix[0][1],constantMatrix[0][0]) , multiplicationPoly(stateMatrix[1][1],constantMatrix[0][1]));
		matrix[1][0]= xorPoly(multiplicationPoly(stateMatrix[0][0],constantMatrix[1][0]) , multiplicationPoly(stateMatrix[1][0],constantMatrix[1][1]));
		matrix[1][1]= xorPoly(multiplicationPoly(stateMatrix[0][1],constantMatrix[1][0]) , multiplicationPoly(stateMatrix[1][1],constantMatrix[1][1]));  
	    
		return matrix;
	}
			
	public static int multiplicationPoly(int a, int b) {
	   // Multiplication in finite field 
	   int result=0;
	   
	   for(int i=0;i<4;i++) {
		   if((b & 1) == 1) {
			   result ^= a;  // xor with previous result : addition in field (addition + xor)
		   }
		   a <<= 1;          // PADDING  : shift a to left  , so that if we encounter '1' , we have a already in the right degree position for multiplication
		   b >>= 1;          // SHIFTING : shift b to right , multiply digit by digit
	   }
	   		   
	   if (result > 0b1111) {
		   // Apply the irreducible polynomial
		   result ^= (0b10011);
		} 
	   return result;
	}
	
	public static int xorPoly(int a, int b) {
		   return (a ^ b);
	}
		
	public static int[][] xorMatrix(int[][] a, int[][] b) {
	    int[][] matrix = new int[2][2];
		   
	    matrix[0][0] = a[0][0] ^ b[0][0];
	    matrix[0][1] = a[0][1] ^ b[0][1];
	    matrix[1][0] = a[1][0] ^ b[1][0];
	    matrix[1][1] = a[1][1] ^ b[1][1];
	  
	    return matrix;
	}
	
	// ******************************************************************************************************* Display results functions
	public static void DisplayMatrix_16(int[][] matrix) {
		for(int i=0;i<2;i++){
			for(int j=0;j<2;j++){
			   System.out.print(Integer.toHexString(matrix[i][j])+" ");
			}
		}
		System.out.println();
	}
	
	public static void DisplayMatrix_32(int[][] matrix) {
		for(int i=0;i<2;i++){
			for(int j=0;j<4;j++){
			   System.out.print(Integer.toHexString(matrix[i][j])+" ");
			}
		}
		System.out.println();
	}
	
	public static void pre_e_MiniAES_16_Data() {
		System.out.println();
		System.out.println("*************** ENCRYPTION (16-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_16(input_16);
	}
	
	public static void post_e_MiniAES_16_Data() {
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_16(output_16);
	}
	
	
	public static void pre_d_MiniAES_16_Data() {
		System.out.println("*************** DECRYPTION (16-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_16(output_16);
	}
	
	public static void post_d_MiniAES_16_Data() {
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_16(output_16);
		System.out.println();
	}
	
	public static void pre_e_MiniAES_32_Data() {
		System.out.println();
		System.out.println("*************** ENCRYPTION (32-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_32(input_32);
		  
	}
	
	public static void post_e_MiniAES_32_Data() {
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_32(output_32);
	}
	
	
	public static void pre_d_MiniAES_32_Data() {
		System.out.println("*************** DECRYPTION (32-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_32(output_32);
	}
	
	public static void post_d_MiniAES_32_Data() {
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_32(output_32);
		System.out.println();
	}
	
	public static void pre_e_MiniAES_CBC_32_Data() {
		System.out.println();
		System.out.println("*************** CBC ENCRYPTION (32-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_32(input_32);
		  
	}
	
	public static void post_e_MiniAES_CBC_32_Data() {
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_32(output_32);
	}
	
	
	public static void pre_d_MiniAES_CBC_32_Data() {
		System.out.println("*************** CBC DECRYPTION (32-bits) ***************");
		System.out.print("PRIVATE KEY : ");
		DisplayMatrix_16(privateKey);
		System.out.print("CIPHER TEXT : ");
		DisplayMatrix_32(output_32);
	}
	
	public static void post_d_MiniAES_CBC_32_Data() {
		System.out.print("PLAIN TEXT  : ");
		DisplayMatrix_32(output_32);
		System.out.println();
	}
	
	public static void Key_observations() {
	       System.out.println();
	       System.out.println("• Key observation:");
	       System.out.println("° ECB Encryption : Identical blocks of plaintext will always produce the same blocks of ciphertext, making it vulnerable to pattern recognition (linearity).");
	       System.out.println("° CBC Encryption : Identical blocks of plaintext will never produce the same blocks of ciphertext.");
	       System.out.println("CBC Encryption's use of chaining and non-linearity ensures that the ciphertext remains unique and resistant to analysis, making it significantly more robust than ECB, and ensuring stronger security.");
	       System.out.println("° Important detail in ECB Encryption : Even when plaintext blocks are identical, intermediate steps like ShiftRow and MixColumns introduce non-linearity.");
	       System.out.println("  This property may alter the internal byte arrangements (you can notice it in the most significant nibble of each byte), but the deterministic nature of ECB still makes it less secure.");
	}
}
	    
    
