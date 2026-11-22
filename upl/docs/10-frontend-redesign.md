# Frontend redesign

The frontend source was restyled to follow the supplied Dhanshiri Bank blue glassmorphism reference.

## Updated screens
- Public landing page with blue gradient hero, CSS-built bank illustration, floating debit-card visual, trust indicators, feature cards, and security banner.
- Login and registration in a split promotional-panel / form-card layout.
- Authenticated workspace with responsive dark-blue sidebar, customer profile, secure-session indicator, and glass-style content panels.
- Customer account, transaction, signed-statement download, and fund-transfer sections retain their existing API calls.
- Branch officer and admin pages inherit the updated workspace, table, form, and security-card styling.
- Public statement verification uses a centered document-authenticity card.

## Functional boundaries
This is a visual redesign of the existing React application. It does not create new banking roles or new backend capabilities. The login still authenticates using the existing username/password plus OTP flow; role authorization remains server-side. The debit-card/building visuals are decorative sample UI, not real account/card data.

## Build
Run `cd frontend && npm ci && npm run build` after extracting the project. The Flask app serves `frontend/dist`, so the production bundle must be rebuilt to see the updated source UI. The production bundle in `frontend/dist` was rebuilt from this source and every page component was rendered once to check it compiles and runs.

## Design
Dark gray theme with one green accent. No external fonts or images are loaded: the Content-Security-Policy only allows the app's own origin, so the page uses system fonts. The layout follows a standard bank site structure (utility bar, main navigation, hero with two selectors, service cards, security section, footer). All text and visuals are original.

## Transfers and duplicates
Every transfer form sends a unique reference. The server stores it with a unique constraint, so a repeat of the same reference returns HTTP 409 and does not move money a second time. A retry after a network error reuses the same reference.

## Admin
The admin page includes the read-only database view and the web security checks panel (listing each control and the automated test that covers it).
