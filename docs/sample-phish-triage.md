# Sample phishing triage

Generated with `socdet phish samples/emails/*.eml --protect samplelending.example`.

## Phishing triage: MALICIOUS (score 100/100)

- **File:** phish-lookalike-invoice.eml
- **Subject:** URGENT: Overdue invoice - wire transfer required within 24 hours
- **From:** ap@sarnplelending.example
- **Authentication:** SPF fail, DKIM none, DMARC fail
- **Links:** 2 · **Attachments:** Invoice_88213.pdf.html

**Why:**
- (+15) SPF result is fail
- (+25) DMARC result is fail
- (+15) replies go to freemail.example, not the sender's domain sarnplelending.example
- (+10) bounce address domain mailer-7731.example.net differs from sarnplelending.example
- (+35) sender domain sarnplelending.example imitates samplelending.example
- (+25) display name 'SampleLending Accounts Payable' uses a trusted name but is sent from sarnplelending.example
- (+15) link points to a bare IP address: http://198.51.100.23/inv/88213
- (+30) link domain samplelending.example.invoice-portal.example.net imitates samplelending.example
- (+20) link text shows portal.samplelending.example but goes to 198.51.100.23
- (+30) attachment type often used for malware: Invoice_88213.pdf.html
- (+20) double extension hides the real file type: Invoice_88213.pdf.html
- (+10) urgency or pressure wording: urgent, immediately, suspended, wire transfer

**Recommended actions:**
- Purge the message from all mailboxes and block the sender domain and link domains.
- Check mail and proxy logs for anyone who clicked or replied; reset credentials for anyone who did.

## Phishing triage: SUSPICIOUS (score 30/100)

- **File:** suspicious-shared-document.eml
- **Subject:** A document has been shared with you
- **From:** notify@docs-share.example.org
- **Authentication:** SPF pass, DKIM pass, DMARC pass
- **Links:** 1 · **Attachments:** none

**Why:**
- (+10) link uses a URL shortener: bit.ly
- (+20) asks the reader to 'verify your account' through a link

**Recommended actions:**
- Hold the message for analyst review before releasing it.
- Ask the reporter whether they clicked.

## Phishing triage: LIKELY BENIGN (score 0/100)

- **File:** benign-newsletter.eml
- **Subject:** October staff newsletter
- **From:** news@samplelending.example
- **Authentication:** SPF pass, DKIM pass, DMARC pass
- **Links:** 1 · **Attachments:** none

**Why:**
- No warning signs found.

**Recommended actions:**
- Thank the reporter and close; no action needed.

