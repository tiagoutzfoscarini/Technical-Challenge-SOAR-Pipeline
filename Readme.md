### Run
First install requirements
> pip install -r requirements.txt

Run with the following syntax:
> python main.py <alert_path>

Here our alerts are stored in 'alerts' folder, so for example:
> python main.py alerts/sentinel.json

### Notes
- I haven't done much of ingestion or data manipulation with Python for Security stuff lately, I have been using mostly PowerShell for what I need, so some stuff here I am not used to. But it is not a big deal as I already know Python from other uses and can learn quickly.
- I have never used Jinja before, so that is totally new for me. I know the tables look bad.
- Enrichment can definitely be optimized, but for this small implementation that is fine. Querying APIs directly or just using a consolidated IOC list from previous queries would allow me to make it much more efficient.