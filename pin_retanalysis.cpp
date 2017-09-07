
/*! @file
 *  This tool detects ROP by inspecting intervals between ret instructions
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

// heuristic parameters
INT32 short_val = 3;
INT32 super_short = 2;
INT32 percent = 90;
INT32 sshort_percent = 50;
INT32 dist_percent = 40;
INT32 dist_threshold = 0xf000;
ADDRINT last_addr = 0;

INT32 ret_window_size = 16;
INT32 interval_len = 0;

std::list<INT32> fifo;
std::list<INT32> address_dists;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "","specify file name for detection result output");

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
    cerr << "This tool detects ret intructions crowding to signal ROP attacks. " << endl;

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
BOOL TooShortIntervals(std::list<INT32> intervals) {
	//cerr << "Called" << "\t";
    INT32 short_intervals = 0;
    INT32 super_short_ints = 0;
    INT32 max_gadget_len = 16;
    INT32 len = (INT32) intervals.size();

    INT32 indx = 0;
    for (std::list<int>::iterator it=intervals.begin(); it != intervals.end(); ++it) {
        if(*it < short_val) short_intervals++;
        if(*it < super_short) super_short_ints++;
        if(*it > max_gadget_len && indx!=1 && indx!=2
            && indx!=3 && indx!=13 && indx!=14 && indx!=15) {
            return FALSE;
        }
        indx++;
    }

    BOOL too_shorts = (((float) short_intervals)/len) > (((float) percent)/100);
    BOOL too_super_shorts = (((float) super_short_ints)/len) > (((float)sshort_percent)/100);

    if(too_shorts && too_super_shorts) {
        *out << "======================================================="<< endl;
        *out << "!!! Too short intervals !!!" << endl;
        *out << "short intervals: " << (((float) short_intervals)/len)*100 << "%" <<endl;
        *out << "super short intervals: " << (((float) super_short_ints)/len)*100 << "%" <<endl;
        *out << "======================================================="<< endl;
        return TRUE;
    }
    return FALSE;
}


BOOL TooLargeDistances(std::list<INT32> dists) {

    INT32 large_dists = 0;
    INT32 len = (INT32) dists.size();

    for (std::list<int>::iterator it=dists.begin(); it != dists.end(); ++it) {
        if(*it > dist_threshold) large_dists++;
    }

    BOOL too_far_instructions = (((float) large_dists)/len) > (((float) dist_percent)/100);

    if(too_far_instructions) {
        *out << "*******************************************************"<< endl;
        *out << "!!! Too far instructions !!!" << endl;
        *out << "large distances: " << (((float) large_dists)/len)*100 << "%" <<endl;
        *out << "*******************************************************"<< endl;
        return TRUE;
    }
    return FALSE;

}


VOID InstructionTrace(TRACE trace, INS ins) {
    // ADDRINT addr = INS_Address(ins);
    // ASSERTX(addr);
    // string astring = FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
    // string traceString = astring + "\t"  + INS_Disassemble(ins);
	// *out << traceString << endl;

    if(fifo.size() > ret_window_size) {
        fifo.pop_front();
        address_dists.pop_front();
        BOOL interval_alert = TooShortIntervals(fifo);
        if(interval_alert) {
            BOOL distance_alert = TooLargeDistances(address_dists);
            if(distance_alert) {
                *out << "ROP DETECTED!" << endl;
            	*out << "Exiting Program..." << endl;
            	exit(-1);
            }
        }
    }

    if(INS_IsRet(ins)) {
        ADDRINT addr = INS_Address(ins);
        INT32 dist = abs((int)(addr - last_addr));
        fifo.push_back(interval_len);
        address_dists.push_back(dist);
        interval_len = 0;
        last_addr = addr;
    } else {
        interval_len++;
    }
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
    *out << "======================================================="<< endl;
    *out <<  "Analysis successfully completed." << endl;
	*out <<  "Exit code: " << code << endl;
	*out <<  "No ROP chain executing detected."<< endl;
    *out << "======================================================="<< endl;
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

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

	//PIN_AddInternalExceptionHandler(catchSegfault, 0);

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is analised by ropdet" << endl;
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
