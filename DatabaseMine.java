/**
 * DatabaseMine class for A4 for CSI2110
 * implements DatabaseInterface
 * 
 * @author Daniel Shwan 300013694
 */
import java.io.UnsupportedEncodingException;

public class DatabaseMine implements DatabaseInterface {

    //instance variables
    private int N, displacements, size;
    private String[] database;
    private double numberOfProbes;

    //constructor
    public DatabaseMine(){
        this.N = 176461;
        this.displacements = 0;
        this.database = new String[N];
        this.numberOfProbes = 0;
        this.size = 0;
    }

    /**
     * Constructor for database
     * 
     * @param N The desired size of the databse
     */
    public DatabaseMine(int N){

        this.N = N;
        this.displacements = 0;
        this.database = new String[N];
        this.numberOfProbes = 0;
        this.size = 0;
    }

    /**
     * Get the address for the value of the key
     * @param key The key for the address
     */
    public int hashFunction(String key) {
        int address=key.hashCode()%N;
        return (address>=0)?address:(address+N);
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

        int hash = hashFunction(encryptedPassword);
        int indexesProbed = 0;

        //Checks if table is full
        if(size == N){
            return "ERROR: Table is full";
        }


        //Checks if there is a value at index hash or if a duplicate is stored
        if(database[hash] == null || plainPassword.equals(database[hash])){
            if(database[hash] == null){
                database[hash] = plainPassword;
                size++;
            }
            else{
                numberOfProbes++;
            }
            return plainPassword;
        }
        else{

            numberOfProbes++;
            //linear probe to store value to avoid collision
            while(indexesProbed != N && (database[hash] != null)){

                //loops stop if a duplicate is found
                if(plainPassword.equals(database[hash])){
                    return plainPassword;
                }
                indexesProbed++;
                hash = (hash + 1)%N;
                numberOfProbes++;
            }
            if(indexesProbed != N){
                database[hash] = plainPassword;
                displacements++;
                size++;
            }
        }
        return null;
    }

    /**
     * Returns plain password corresponding to encrypted password
     * 
     * @param encryptedPassword Key for value to be found
     * @return The decrypted version of the password
     */
    public String decrypt(String encryptedPassword){
        
        int hash = hashFunction(encryptedPassword);
        int indexesProbed = 0;
        
        try{
            while(indexesProbed != N){
                String value = database[hash];

                if(value == null){
                    return "No such key exists";
                }
                else if(Sha1.hash(database[hash]).equals(encryptedPassword)){
                    return database[hash];
                }
                else{
                    hash = (hash + 1)%N;
                    indexesProbed++;
                    numberOfProbes++;
                }
            }
        }
        catch(UnsupportedEncodingException e){
            System.out.println("ERROR: !! UnsupportedEncodingException occured !!");
        }
        
        return "No such key exists"; 
    }

    /**
     * returns the number of password pairs stored in the database
     * 
     * @return The size of the database
     */
    public int size(){return size;}

    /**
     * print statistics about the Database
     */
    public void printStatistics(){
        System.out.println("*** DatabaseMine Statistics ***");
        System.out.println("Size is " + size() + " passwords");
        System.out.println("Number of Indexes: " + N);
        System.out.println("Load Factor is: " + (double)size/N);
        System.out.println("Average Number of Probes is " + (double)Math.round((numberOfProbes/size())*10)/10.0);
        System.out.println("Number of Displacements (from Collision): " + displacements);
        System.out.println("*** End DatabaseMine Statistics ***");
    }
}