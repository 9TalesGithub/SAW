//Finds all the write locations for a particular variable
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.ArrayList;

public class c3script extends GhidraScript {

    public void run() throws Exception {
	Program program = currentProgram;

        //================== Get the function ===================
	FunctionManager functionManager = program.getFunctionManager();
        boolean functionFound = false;
	boolean incorrectFunctionEntered = false;
	boolean functionHasVariables = true;
	ArrayList<Function> desiredFunctions = new ArrayList<Function>();
	String desiredFunctionString = "";

        while (!functionFound) {
            //Get the function name
	    if (!functionHasVariables) {
	        desiredFunctionString = askString("Function Name", "The function \"" + desiredFunctionString + "\" exists but doesn't have any variables. What function are you checking the variables from?");
	    }
	    else if (incorrectFunctionEntered) {
	        desiredFunctionString = askString("Function Name", "The function \"" + desiredFunctionString + "\" does not exist. What function are you checking the variables from?");
	    }
	    else {
                desiredFunctionString = askString("Function Name", "What function are you checking the variables from?");
	    }

	    //Reinitializing functionHasVariables so the script doesn't give the wrong message when a function doesn't exist if the previous function didn't have variables
	    functionHasVariables = true;

            //Determine if the function exists
            FunctionIterator allFunctions = functionManager.getFunctions(true);
            while (allFunctions.hasNext()) {
                Function currentFunction = allFunctions.next();

                //if this is the desired function
                if (desiredFunctionString.equals(currentFunction.getName())) {
		    if (currentFunction.getLocalVariables().length == 0) {
			//It exists, but doesn't have any variables
			functionHasVariables = false;
		    }
		    else {
			//A valid function of that name was found
                        desiredFunctions.add(currentFunction);
                        functionFound = true;
		    }
                }
            }

            //Add an error message to the prompt if the while loop runs again
            incorrectFunctionEntered = true;
        }
	

        //================== Get the variable ===================
        boolean variableFound = false;
	boolean incorrectVariableEntered = false;
        String desiredVariableString = "";
	ArrayList<Variable> desiredVariables = new ArrayList<Variable>();

        while (!variableFound) {
            //Get the variable name
	    if (incorrectVariableEntered) {
		desiredVariableString = askString("Variable Name", "There is no variable by the name \"" + desiredVariableString + "\" in any function with the name \"" + desiredFunctionString + "\". What variable do you want to check for modifications of?");
	    }
	    else {
                desiredVariableString = askString("Variable Name", "What variable do you want to check for modifications of in the function \"" + desiredFunctionString + "\"?");
	    }

            //Determine if the variable exists
	    for (int i = 0; i < desiredFunctions.size(); i++) {
                Variable[] functionVariables = desiredFunctions.get(i).getLocalVariables();
                for (Variable vari : functionVariables) {
                    if (desiredVariableString.equals(vari.getName())) {
                        variableFound = true;
		        desiredVariables.add(vari);
                        break;
                    }
                }
	    }

            //Add an error message to the prompt if the while loop runs again
            incorrectVariableEntered = true;
        }
        
        //================== Find all write locations to that variable ==================
	//Printing how many functions had that variable if there wasn't just one
	if (desiredVariables.size() != 1) {
	    println("The variable \"" + desiredVariableString + "\" exists in " + desiredVariables.size() + " functions with the name \"" + desiredFunctionString + "\". Here are the results for each of them.");
	}

	ReferenceManager referenceManager = program.getReferenceManager();
	
	//Iterating through each function
	for (Variable desiredVariable : desiredVariables) {
	    println("The following write locations for variable \"" + desiredVariableString + "\" in function \"" + desiredFunctionString + "\" at address " + desiredVariable.getFunction().getEntryPoint().toString() + " were found:");
	    boolean writeLocationsFound = false;   
	

	    //Get the references to the variable         
	    Reference[] desiredVariableReferences = referenceManager.getReferencesTo(desiredVariable);      
	
	
	    //Iterate over the references and determine if they are writes to the variable        
	    for (Reference reference : desiredVariableReferences) {
	        if (reference.getReferenceType().isWrite()) {             
	            // Get the instruction that writes to the variable             
	            Instruction instruction = getInstructionAt(reference.getFromAddress());              

	            // Print the address where the variable is written             
	            println("Address " + instruction.getAddress());  

	            writeLocationsFound = true; 
	        }      
	    }      
	  


	    if (!writeLocationsFound) {
	        println("No write locations found.");
	    }
	}

	popup("Results are shown in the console.");
    }
}
