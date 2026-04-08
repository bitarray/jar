import VersoManual
import Jar.Merkle
import Jar.State

open Verso.Genre Manual
open Jar.Merkle

set_option verso.docstring.allowMissing true

#doc (Manual) "Merkle Structures" =>

Merkle trie, binary Merkle tree, and Merkle Mountain Range constructions
used for state commitment and availability (GP Appendix D-E).

# Trie Nodes

{docstring Jar.Merkle.Node}

{docstring Jar.Merkle.encodeBranch}

{docstring Jar.Merkle.encodeLeaf}

# State Trie

The trie uses fixed-length bit-string keys: 31-byte keys (248 bits) for state
commitment and 32-byte keys for work-report Merkle roots.

{docstring Jar.Merkle.trieRoot}

{docstring Jar.Merkle.trieRoot32}

{docstring Jar.Merkle.stateRoot}

# Binary Merkle Tree

{docstring Jar.Merkle.binaryMerkleRoot}

{docstring Jar.Merkle.constDepthMerkleRoot}

# Merkle Mountain Range (Appendix E)

{docstring Jar.mmrAppend}

{docstring Jar.mmrSuperPeak}
