import Jar
import VersoManual

open Verso.Genre Manual

#doc (Manual) "JAR Lean Spec" =>

%%%
tag := "jar-lean-spec"
authors := ["JAR Contributors"]
%%%

The Lean tree specifies the decided JAR design up to the JAVM kernel level:
SSZ data layout, the PVM2 RV64E execution envelope, capabilities, kernel
resources, yield routing, SubVM invocation, and the aggregate JAVM state.

Genesis Proof-of-Intelligence scoring remains in the separate `Genesis`
library.
