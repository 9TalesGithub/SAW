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

public class c3script extends GhidraScript {

	public void run() throws Exception {
		Program program = currentProgram;
		FunctionManager functionManager = program.getFunctionManager();
	
	    	//================== Get the function ===================
	        boolean functionFound = false;
		boolean incorrectFunctionEntered = false;
		boolean functionHasVariables = true;
		Function desiredFunction = getFirstFunction();
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
	
		        //Reinitializing some error message related variables
		        incorrectFunctionEntered = false;
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
				        	break;
			            	}
			            	else {
	                        		desiredFunction = currentFunction;
	                        		functionFound = true;
	                        		break;
			            	}
	                	}
	            	}
	
	            	//Add an error message if the function doesn't exist (this also gets entered if it doesn't have variables, but that has no effect)
	            	if (!functionFound) {
	                	incorrectFunctionEntered = true;
	            	}
	        }
		
	
	        //================== Get the variable ===================
	        boolean variableFound = false;
		boolean incorrectVariableEntered = false;
		Variable desiredVariable = desiredFunction.getLocalVariables()[0];
	        String desiredVariableString = "";
	
	        while (!variableFound) {
	        	//Get the variable name
			if (incorrectVariableEntered) {
				desiredVariableString = askString("Variable Name", "There is no variable by the name \"" + desiredVariableString + "\" in the function \"" + desiredFunctionString + "\". What variable do you want to check for modifications of?");
			}
		        else {
	                	desiredVariableString = askString("Variable Name", "What variable do you want to check for modifications of in the function \"" + desiredFunctionString + "\"?");
		        }
	
	            	//Determine if the variable exists
	            	Variable[] functionVariables = desiredFunction.getLocalVariables();
	            	for (Variable vari : functionVariables) {
	                	if (desiredVariableString.equals(vari.getName())) {
	                    		variableFound = true;
			            	desiredVariable = vari;
	                    		break;
	                	}
	            	}
	
	            	//Add an error message if the variable does not exist
	            	if (!variableFound) {
	                	incorrectVariableEntered = true;
	            	}
	        }
	        
	        //================== Find all write locations to that variable ==================
		println("The following write locations for variable \"" + desiredVariableString + "\" in function \"" + desiredFunctionString + "\" were found:");
		boolean writeLocationsFound = false;   
		ReferenceManager referenceManager = program.getReferenceManager();
	
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
	
		popup("Results are shown in the console.");
	}
}
