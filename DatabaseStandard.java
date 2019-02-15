/**
 * DatabaseStandard class for A4 for CSI2110
 * implements DatabaseInterface
 * 
 * @author Daniel Shwan 300013694
 */
import java.util.HashMap;

public class DatabaseStandard implements DatabaseInterface{

    //Instance Variables
    private HashMap<String,String> database;
    private int index;

    //Constructor
    public DatabaseStandard(){
        this.index = 37;
        this.database = new HashMap<>(index);
    }

    /**
     * Stores plainPassword and corresponding encryptedPassword in a map.
     * if there was a value associated with this key, it is replaced, 
     * and previous value returned; otherwise, null is returned
     * The key is the encryptedPassword the value is the plainPassword
     * 
     * @param plainPassword value to be stored
     * @param encryptedPassword key of value
     * 
     * @return String that has been replaced or null if no initial value at key  
     */
    public String save(String plainPassword, String encryptedPassword){
        String returnString = null;

        if(database.get(encryptedPassword) == null){
            database.put(encryptedPassword, plainPassword);
        }
        else{
            returnString = database.replace(encryptedPassword, plainPassword);
        }

        return returnString;
    } 

    /**
     * Returns plain password corresponding to encrypted password
     * 
     * @param encryptedPassword Key for value to be found
     * @return The decrypted version of the password
     */
    public String decrypt(String encryptedPassword){return database.get(encryptedPassword);}

    /**
     * returns the number of password pairs stored in the database
     * 
     * @return The size of the database
     */
    public int size(){return database.size();}

    /**
     * print statistics about the Database
     */
    public void printStatistics(){
        System.out.println("*** DatabaseStandard Statistics ***");
        System.out.println("Size is " + size() + " passwords");
        System.out.println("Initial Number of Indexes when Created: " + index);
        System.out.println("*** End DatabaseStandard Statistics ***");
    }
}