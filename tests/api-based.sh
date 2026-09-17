baseURL="http://localhost:8080"
cookieJar="cookies.txt"
rm -f "$cookieJar"

echo "==> Register a new user"
endpoint="/v1/register"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123" \
     --data-urlencode "password=secret123" \
     --cookie-jar "$cookieJar"

echo -e "\n==> Try to access the protected endpoint without cookie (should fail)"
endpoint="/v1/protected"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123"

echo -e "\n==> Login with the registered user"
endpoint="/v1/login"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123" \
     --data-urlencode "password=secret123" \
     --cookie-jar "$cookieJar" \
     --cookie "$cookieJar"

echo -e "\n==> Try to access the protected endpoint without cookie but with session (should fail)"
endpoint="/v1/protected"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123"

echo -e "\n==> Extract the CSRF token from the cookie jar"
csrfToken=$(grep 'csrf_token' "$cookieJar" | head -n 1 | cut -f7)

echo -e "\n==> Access the protected endpoint with session cookie + CSRF header (should succeed)"
endpoint="/v1/protected"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123" \
     --header "X-Csrf-Token: $csrfToken" \
     --cookie "$cookieJar"

echo -e "\n==> Logout the user"
endpoint="/v1/logout"
curl --request POST \
     --include \
     --url "$baseURL$endpoint" \
     --data-urlencode "username=testuser123" \
     --header "X-Csrf-Token: $csrfToken" \
     --cookie "$cookieJar"

rm -f "$cookieJar"
