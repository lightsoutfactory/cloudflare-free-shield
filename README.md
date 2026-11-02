# cloudflare-free-shield

Three Cloudflare WAF custom rules that stop most scraper floods at Cloudflare's edge, all possible on the **Free
plan**, installed, switched and rolled back with one Python file and no dependencies.

We wrote them after a scraper behind residential proxies took one of our sites down for about ten hours: thousands
of home addresses with one to three requests each, Chrome user agents, about 225 requests a second. Per-address rate
limits never fire on traffic like that. These rules look at what such traffic lacks instead. The whole story,
with what we saw in the logs, is in our [field notes](https://lightsoutfactory.ai/field-notes/scraper-flood-cloudflare-free-plan/).

| Rule | Default | Matches (GET requests for pages) | Action |
|---|---|---|---|
| fake browser | on | the user agent says `Chrome/`, but there is no `Sec-Fetch-Mode` header | managed challenge |
| scraper clouds | on | the client is on Alibaba, Tencent or Huawei Cloud (`--asns` to change) | managed challenge |
| emergency | off | no cookie at all and no Referer | managed challenge |

Every rule lets through Cloudflare's verified bots, user agents that name themselves as robots (bot, crawl, spider,
preview, google, lighthouse), your `--allow-ips`, the paths in `--skip-paths` (default `/api/ /webhook`) and files that
are not pages. Switch the emergency rule on during a flood: people with a cookie or arriving through a link pass
untouched, and a scraper that keeps no cookies meets a challenge on every request. It is off normally because it also
challenges someone who types your address into a fresh browser.

## Install

```sh
pip install git+https://github.com/lightsoutfactory/cloudflare-free-shield
```

That gives you the `cf-free-shield` command; `python3 cf_free_shield.py` does the same from a copy of the one file.

## Use

```sh
export CLOUDFLARE_API_TOKEN=...      # a token with Zone: Read and Zone WAF: Edit for your zones
python3 cf_free_shield.py rules                                   # see the exact expressions first
python3 cf_free_shield.py install example.com --allow-ips "203.0.113.7" --dry-run
python3 cf_free_shield.py install example.com --allow-ips "203.0.113.7"
python3 cf_free_shield.py status all
python3 cf_free_shield.py on example.com        # during a flood
python3 cf_free_shield.py off example.com
python3 cf_free_shield.py restore example.com   # put back the rules saved before the last change
```

The shield uses three of the five custom rules the Free plan gives each zone. Your own rules are kept, ahead of these.
Every change first saves the zone's rules to `./shield-backups/<zone>/`.

## What we leave switched off in Cloudflare, and why

- **Bot Fight Mode**: it cannot be skipped by a custom rule on the Free plan, and it challenged our payment provider's
  webhooks.
- **Under Attack mode for the whole zone**: every visitor, API client and webhook gets the interstitial. The emergency
  rule challenges only strangers' page requests.
- **The Free plan's rate-limiting rule**: it counts per address, and a residential-proxy flood sends one to three
  requests per address.

## The rest of the kit

This is the Cloudflare part of **[Night Watch](https://lightsoutfactory.ai/kits/night-watch/)**, which also:
watches every site you run and emails you when one goes down and when it is back, switches the emergency rule on by
itself when a site falls over from overload (and off again hours later), summarises what Cloudflare's firewall
challenged by network, country, user agent and path, and adds a bot gate inside your Python app for the floods that get
past the edge. The story of the flood that started it: [field notes](https://lightsoutfactory.ai/field-notes/scraper-flood-cloudflare-free-plan/).

Also free from us: [bot-gate](https://github.com/lightsoutfactory/bot-gate) (keep pages up for people during a scraper
flood), [translation-checks](https://github.com/lightsoutfactory/translation-checks) (catch translations that would
break your app) and [vllm-health](https://github.com/lightsoutfactory/vllm-health) (a vLLM health check that never waits
in the queue).

MIT licence.
