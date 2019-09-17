
import java.util.ArrayList;
import java.io.UnsupportedEncodingException;

public class PasswordCracker{

    /**
     * Creates and fills password database
     * 
     * @param commonPasswords arraylist of all password
     * @param database The database
     */
    public void createDatabase(ArrayList<String> commonPasswords, DatabaseInterface database){
        try{
            String tempPassword;
            for(String password: commonPasswords){
                tempPassword = password.concat("2018");

                if(!(password.matches("[0-9]+"))){

                    addMutatedPassword(password, database);
                    addMutatedPassword(tempPassword, database);

                    if(Character.isLowerCase(password.charAt(0))){
                        tempPassword = password.substring(0, 1).toUpperCase() + password.substring(1);
                        database.save(tempPassword, Sha1.hash(tempPassword));
                        addMutatedPassword(tempPassword, database);

                        tempPassword = tempPassword.concat("2018");
                        database.save(tempPassword, Sha1.hash(tempPassword));
                        addMutatedPassword(tempPassword, database);
                    }
                }
                else{
                    database.save(password, Sha1.hash(password));
                    database.save(tempPassword, Sha1.hash(tempPassword));
                }
            }
        }
        catch(UnsupportedEncodingException e){
            System.out.println("!! UNSUPPORTED ENCODING EXCEPTION CAUGHT !!");
        }
    }

    /**
     * Find the plain password of the encrypted password
     * 
     * @param encryptedPassword The encrypted password/key
     * @param database The database
     * 
     * @return decrypted password
     */
    public String crackPassword(String encryptedPassword, DatabaseInterface database) {

        String decryptedPassword = database.decrypt(encryptedPassword);

        if(decryptedPassword == null){
            return "ERROR: No password found in database";
        }
        return decryptedPassword;
    }

    /**
     * Adds all permutations of string with characters a,e, or/and i
     * 
     * @param password The password
     * @param database The database
     * @throws UnsupportedEncodingException
     */
    private void addMutatedPassword(String password, DatabaseInterface database) throws UnsupportedEncodingException{
    
        int numberOfA, numberOfE, numberOfI;
        int[] charIndexA, charIndexE, charIndexI;
        boolean aExists, eExists, iExists;
        ArrayList<String> permutationsA, permutationsE, permutationsI;

        numberOfA = findNumberOfOccurence(password,'a');
        numberOfE = findNumberOfOccurence(password,'e');
        numberOfI = findNumberOfOccurence(password,'i');
        aExists = eExists = iExists = false;

        charIndexA = indexOfCharAt(password, 'a', numberOfA);
        charIndexE = indexOfCharAt(password, 'e', numberOfE);
        charIndexI = indexOfCharAt(password, 'i', numberOfI);

        if(numberOfA != 0){aExists = true;}
        if(numberOfE != 0){eExists = true;}
        if(numberOfI != 0){iExists = true;}

        //Adds all the different combinations of the string with char a,e, or i into the database
        if(aExists){
            permutationsA = permutations(password, 'a', charIndexA); 

            for(String permutation: permutationsA){

                if(eExists){
                    permutationsE = permutations(permutation, 'e', charIndexE);

                    for(String tempPassword: permutationsE){

                        if(iExists){
                            permutationsI = permutations(tempPassword, 'i', charIndexI);

                            for(String finalPermutation: permutationsI){
                                database.save(finalPermutation, Sha1.hash(finalPermutation));
                            }
                        }
                        else{
                            database.save(tempPassword, Sha1.hash(tempPassword));
                        }
                    }
                }
                else if(iExists){
                    permutationsI = permutations(permutation, 'i', charIndexI);

                    for(String finalPermutation: permutationsI){
                        database.save(finalPermutation, Sha1.hash(finalPermutation));
                    }
                }
                else{
                    database.save(permutation, Sha1.hash(permutation));
                }
            }
        }
        else if(eExists){
            permutationsE = permutations(password, 'e', charIndexE);
            for(String permutation: permutationsE){
                if(iExists){
                    permutationsI = permutations(permutation, 'i', charIndexI);
                    for(String permutation2: permutationsI){
                        database.save(permutation2, Sha1.hash(permutation2));
                    }
                }
                else{
                    database.save(permutation, Sha1.hash(permutation));
                }
            }
        }
        else{
            permutationsI = permutations(password, 'i', charIndexI);
            for(String permutation: permutationsI){
                database.save(permutation, Sha1.hash(permutation));
            }
        }
    }

    /**
     * Find index of characters: a,e, or i in the string
     * 
     * @param str The password
     * @param character The character to find
     * @param occurence The number of that character in the string
     * 
     * @return The index positions of the characters in the string
     */
    private int[] indexOfCharAt(String str, char character, int occurence){

        int[] charIndexes = new int[occurence];
        int index = 0;

        for (int i = 0; i < str.length(); i++){
            if (str.charAt(i) == character){
                charIndexes[index] = i;
                index++;
            }
        }
        return charIndexes;
    }

    /**
     * Finds how many times a character appears in the stringf
     * 
     * @param password The password
     * @param c The character to find
     * 
     * @return The number of times character c appears in string password
     */
    private int findNumberOfOccurence(String password, char c){

        int occurences = 0;

        for(int i = 0; i < password.length(); i++){
            if(password.charAt(i) == c){
                occurences++;
            }          
        }
        return occurences;
    }

    /**
     * Find all permutations of a password with character c
     * 
     * @param password The password
     * @param c The character
     * @param charIndex The index position of char c
     * 
     * @return An arraylist of all permutations of the string
     */
    private ArrayList<String> permutations(String password, char c, int[] charIndex){
 
        char replacementChar;
        ArrayList<String> permutations = new ArrayList<String>();
        char[] psswrd = password.toCharArray();
        permutations.add(password);

        if(c == 'a'){
            replacementChar = '@';
        }
        else if(c == 'e'){
            replacementChar = '3';
        }
        else{
            replacementChar = '1';
        }
        
        binaryLikePermutation(psswrd,permutations, charIndex,replacementChar, c);
        
        return permutations;
    }

    /**
     * Adds all possible permutation to arraylist
     * 
     * @param password Password as a char array
     * @param permutations The arraylist to fill
     * @param charIndex The index of char to permutate
     * @param replacementChar The char to replace the char c
     * @param c The char to find
     */
    private void binaryLikePermutation(char[] password, ArrayList<String> permutations, int[] charIndex, char replacementChar, char c){

        int index = 0;

        while(index != charIndex.length){

            if(password[charIndex[index]] == c){
                password[charIndex[index]] = replacementChar;
                permutations.add(String.valueOf(password));
                index = -1;
            }
            else{
                password[charIndex[index]] = c;
            }
            index++;
        }
        return;
    }
}