
/*! @file
 *  This tool traces the disassembly of each instruction
 */

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "pin.H"
#include "instlib.H"
#include "control_manager.H"

using namespace CONTROLLER;
using namespace INSTLIB;
/* ================================================================== */
// Global variables
/* ================================================================== */

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "insdisas.out","specify file name for instruction disassembly output");

KNOB<BOOL>   KnobSymbols(KNOB_MODE_WRITEONCE, "pintool",
	"symbols", "1", "Include symbol information");
/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints the address and name of each executed instruction " << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

string FormatAddress(ADDRINT address, RTN rtn)
{
	string s = StringFromAddrint(address);

	if (KnobSymbols && RTN_Valid(rtn))
	{
		IMG img = SEC_Img(RTN_Sec(rtn));
		s += " ";
		if (IMG_Valid(img))
		{
			s += IMG_Name(img) + ":";
		}

		s += RTN_Name(rtn);

		ADDRINT delta = address - RTN_Address(rtn);
		if (delta != 0)
		{
			s += "+" + hexstr(delta, 4);
		}
	}
	return s;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
VOID InstructionTrace(TRACE trace, INS ins) {

    ADDRINT addr = INS_Address(ins);
    ASSERTX(addr);

    // Format the string at instrumentation time
    //string traceString = "";
    string astring = FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
    //for (INT32 length = astring.length(); length < 30; length++) {
    //    traceString += " ";
    //}
    string traceString = astring + "\t"  + INS_Disassemble(ins);

    //for (INT32 length = traceString.length(); length < 80; length++) {
    //    traceString += " ";
    //}

	*out << traceString << endl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Call instruction analysis function for each instruction.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
                InstructionTrace(trace, ins);
        }
    }
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "Analysis successfully completed." << endl;
	*out <<  "Exit code: " << code << endl;
    *out <<  "===============================================" << endl;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if( PIN_Init(argc,argv) ) { return Usage(); }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str()); }

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by insdisas" << endl;
    if (!KnobOutputFile.Value().empty()) {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
