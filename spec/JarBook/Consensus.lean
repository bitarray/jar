import VersoManual
import Jar.Consensus

open Verso.Genre Manual
open Jar.Consensus

set_option verso.docstring.allowMissing true

#doc (Manual) "Safrole Consensus" =>

The Safrole block-production mechanism — a SNARK-based, slot-auction
consensus protocol (GP §6).

# Block Sealing

{docstring Jar.Consensus.outsideInSequencer}

{docstring Jar.Consensus.fallbackKeySequence}

{docstring Jar.Consensus.verifySealTicketed}

{docstring Jar.Consensus.verifySealFallback}

{docstring Jar.Consensus.verifyEntropyVrf}

# Ticket Accumulation

{docstring Jar.Consensus.verifyTicketProof}

{docstring Jar.Consensus.accumulateTickets}

# State Update

{docstring Jar.Consensus.updateSafrole}

# Chain Selection

{docstring Jar.Consensus.chainMetric}

{docstring Jar.Consensus.isAcceptable}
