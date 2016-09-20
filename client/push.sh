#!/bin/sh

curl -H "Authorization: key=AIzaSyClmtjNkWi5mycp9ZVpw6NeZCUW3xWD2LU" \
    -H "Content-Type: application/json" \
    https://android.googleapis.com/gcm/send \
    -d "{\"registration_ids\":[\"dx018onL-mU:APA91bHQ_nP3VRpD4Ci_R1t8ljLuFRvQEflYDeROmbuouFvm6KQT430MHrgNaXcq-98Wn59kU-mFMzuk8hilwGtaoMS0DUZ4sNe-ZBjYp2DSuAGTDB2g6s4kbvp3VBC25LE_pR2OcVg8\"]}"
