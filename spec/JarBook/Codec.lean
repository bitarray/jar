import VersoManual
import Jar.Codec

open Verso.Genre Manual
open Jar.Codec

set_option verso.docstring.allowMissing true

#doc (Manual) "Serialization Codec" =>

Binary encoding of protocol types for hashing and network transmission (GP Appendix C).
All encodings are little-endian.

# Primitive Encoders

{docstring Jar.Codec.encodeFixedNat}

{docstring Jar.Codec.decodeFixedNat}

{docstring Jar.Codec.encodeNat}

{docstring Jar.Codec.encodeOption}

{docstring Jar.Codec.encodeLengthPrefixed}

{docstring Jar.Codec.encodeBits}

# Work Types

{docstring Jar.Codec.encodeWorkResult}

{docstring Jar.Codec.encodeAvailSpec}

{docstring Jar.Codec.encodeRefinementContext}

{docstring Jar.Codec.encodeWorkDigest}

{docstring Jar.Codec.encodeWorkReport}

# Extrinsic Encoders

{docstring Jar.Codec.encodeTicket}

{docstring Jar.Codec.encodeTicketProof}

{docstring Jar.Codec.encodeAssurance}

{docstring Jar.Codec.encodeGuarantee}

{docstring Jar.Codec.encodeDisputes}

{docstring Jar.Codec.encodePreimages}

# Block Encoding

{docstring Jar.Codec.encodeEpochMarker}

{docstring Jar.Codec.encodeUnsignedHeader}

{docstring Jar.Codec.encodeHeader}

{docstring Jar.Codec.encodeExtrinsic}

{docstring Jar.Codec.encodeBlock}
