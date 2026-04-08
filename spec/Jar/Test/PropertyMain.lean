import Jar.Test.Properties
import Jar.Test.Arbitrary
import Jar.Variant

open Jar Jar.Test.Arb

def propertyMain : IO UInt32 := do
  letI := JarVariant.gp072_tiny.toJarConfig
  -- Provide variant-specific Arbitrary instances for EconType/TransferType.
  -- gp072_tiny uses BalanceEcon/BalanceTransfer.
  letI : Plausible.Arbitrary (JarConfig.EconType) := instArbitraryBalanceEcon
  letI : Plausible.Arbitrary (JarConfig.TransferType) := instArbitraryBalanceTransfer
  Jar.Test.Properties.runAll
