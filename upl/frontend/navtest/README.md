Click-flow test (jsdom). It opens the app in a simulated browser and clicks through every navigation path:
landing, log in, create account, back to home, dashboard, log out.

Run from the frontend folder, after `npm ci`:

    npm i --no-save jsdom@24
    npx esbuild navtest/entry.jsx --bundle --format=iife --platform=browser --jsx=automatic --outfile=navtest/bundle.js
    cd navtest && node nav.cjs

Each line prints PASS or FAIL. The test runs the real React code with mocked API responses.
