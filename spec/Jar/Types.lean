import Jar.Types.Constants
import Jar.Types.Numerics
import Jar.Types.Validators
import Jar.Types.Work
import Jar.Types.Accounts
import Jar.Types.Header
import Jar.Types.State

/-!
# Core Types — Gray Paper §3–4, §5–6, §9–14

The complete Gray Paper type universe, organized into sub-modules:
- `Types.Constants`  — Protocol constants (Appendix I.4.4)
- `Types.Numerics`   — Bounded numeric types (§3.4, §4.6–4.7)
- `Types.Validators`  — Validator keys, tickets, Safrole state (§6)
- `Types.Work`       — Work reports, digests, packages (§11, §14)
- `Types.Accounts`   — Service accounts, privileged services (§9, §12)
- `Types.Header`     — Block, Header, Extrinsic (§4–5)
- `Types.State`      — Complete chain state σ (§4.2)
-/
