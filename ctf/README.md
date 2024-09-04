---
permalink: /ctf
layout: base
---
{% for page in site.pages %}
{% if page.url contains '/ctf/' %}
- [{{ page.title }}]({{ page.url }})
{% endif %}
{% endfor %}