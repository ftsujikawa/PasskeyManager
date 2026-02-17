# Google OAuth State Test Checklist

## Preconditions
- Build target: packaged app (MSIX)
- `appsetting.local.json` has valid Google OAuth credentials
- Network access is available

## Test Cases

### 1) First sign-in (no saved token)
1. Ensure token file does not exist:
   - `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\tsupasswd\google_refresh_token.bin`
2. Launch app and open MainPage.
3. Confirm button text is `Google Sign-in` and Disconnect is disabled.
4. Click `Google Sign-in`.
5. Expected:
   - Browser opens once.
   - Log contains `Google OAuth complete (refresh_token saved)`.
   - Button text changes to `Google Connected`.
   - `Google Sign-in` is disabled and Disconnect is enabled.

### 2) Reuse saved token (skip browser)
1. Relaunch app.
2. Confirm button text is `Google Connected`.
3. Click `Google Connected` button (disabled, cannot be clicked).
4. Expected:
   - Browser does not open.
   - No new OAuth flow starts.

### 3) Disconnect flow
1. Click `Disconnect`.
2. Expected:
   - Log contains `Google refresh_token removed. Sign-in required next time.`
   - Button text returns to `Google Sign-in`.
   - Disconnect becomes disabled.
   - Token file is removed.

### 4) Sign-in after disconnect
1. Click `Google Sign-in`.
2. Expected:
   - Browser opens once.
   - OAuth completes and token file is created again.
   - UI returns to connected state.

### 5) Multi-click guard
1. With no saved token, click `Google Sign-in` repeatedly.
2. Expected:
   - While flow is in progress, additional starts are blocked.
   - Warning log appears: `Google OAuth is already in progress...`.

## Pass Criteria
- No unexpected browser relaunch while connected.
- UI state and token file state stay consistent after sign-in/disconnect/restart.
- No `state mismatch` caused by double-start from UI.
