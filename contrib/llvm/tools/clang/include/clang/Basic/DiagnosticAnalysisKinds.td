//==--- DiagnosticAnalysisKinds.td - libanalysis diagnostics --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

let Component = "Analysis" in {

// CHECK: use of uninitialized values
def warn_uninit_val : Warning<"use of uninitialized variable">;

}
