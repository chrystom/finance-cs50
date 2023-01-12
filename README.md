# finance-cs50
### What is it?
A website that uses IEX's realtime market API to make a sort of-stock simulator where the user can register, login, log out, change their password and most importantly, view, buy and sell stocks.

This site primarily uses Flask, IEX's API and CS50's SQL library

### Getting an API Key and starting the dev server
- Visit iexcloud.io/cloud-login#/register/.
- Select the “Individual” account type, then enter your name, email address, and a password, and click “Create account”.
- Once registered, scroll down to “Get started for free” and click “Select Start plan” to choose the free plan.
- Once you’ve confirmed your account via a confirmation email, visit https://iexcloud.io/console/tokens.
- Copy the key that appears under the Token column (it should begin with `pk_`).
- If you are using a Linux distribution, open `run.sh` and paste the key directly after the `=` and run it (you may need to set the script to executable).
- If you are using Windows, open `run.cmd` and paste the key directly after the `=` and run it.
