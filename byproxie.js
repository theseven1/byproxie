/**
 * byproxie enterprise proxy detection engine - cdn edition
 * version: 4.1.1-cdn
 */

(function (global) {
    "use strict";

    if (global.ByProxie) return; // prevent double instantiation

    // preserve native references before proxy scripts can mock them
    // natively bound functions require .bind(global) to prevent 'illegal invocation'
    const NATIVE = {
        fetch:              global.fetch.bind(global),
        XMLHttpRequest:     global.XMLHttpRequest,
        XHROpen:            global.XMLHttpRequest.prototype.open,
        WebSocket:          global.WebSocket,
        Worker:             global.Worker,
        SharedWorker:       global.SharedWorker,
        WasmInstantiate:    global.WebAssembly?.instantiate,
        SWRegister:         global.navigator?.serviceWorker?.register?.bind(global.navigator.serviceWorker),
        historyPushState:   global.history?.pushState,
        historyReplaceState:global.history?.replaceState,
        postMessage:        global.postMessage.bind(global),
        dispatchEvent:      global.document.dispatchEvent.bind(global.document),
        CustomEvent:        global.CustomEvent,
        crypto:             global.crypto,
        MutationObserver:   global.MutationObserver,
        setTimeout:         global.setTimeout.bind(global),
        setInterval:        global.setInterval.bind(global),
        ResponseText:       global.Response?.prototype?.text
    };

    // default detection rulesets
    const DEFAULT_RULES = {
        urlPatterns: [
            /\/uv\/(uv\.(config|bundle|sw|handler|client)\.js)/i,
            /\/scramjet\/(scramjet\.|worker\.|shared\.)/i,
            /\/baremux\/(worker|index)\.js/i,
            /\/epoxy\/(index|worker)?\.js/i,
            /\/libcurl\/(index|worker)?\.js/i,
            /\/wisp(?:[-_]server)?\//i,
            /\/bare\/v[0-9]+\//i,
            /\/corrosion\/|\/corro\.sw\.js/i,
            /\/rammerhead\//i,
            /wss?:\/\/[^/]+\/wisp\//i,
        ],
        keywords: [
            'scramjet', 'ultraviolet', 'baremux', 'epoxy', 'wisp-server', 
            '__uv$config', 'ScramjetController', 'BareMuxConnection',
            'rammerhead', 'corrosion', 'womginx', '__alloy', 'proxy.hidester.one', '__cpp'
        ],
        hashes: new Set([
            "984c191bd436798ff150dfd1f88aead29579080bfc1e1f3aa2ea3443b83d97f8",
            "6146987c60ff35534b4b431e6d1efbd1da035900e4073ddc7b945c8f30f467bf",
            "c4bea1d1e4de1748e1cccb42dedf3fe1297fcc9218885e6b06bb9d26aeb279c5",
            "9f768fe9e3a442a15c34712ae3ab4ef8fb1ec903953398253d03e61c612f47b0",
            "2990084f91653e1687f6c11094be4cabb59e9a2141373f63b577442304f9ad51",
            "2ec4be58481adf0e2dae132488d4cf2a42f4d765f6f1f802254e9517610a6074",
            "2593f58b7f3fc5618bc8c0f6735b1af8af22330eb46a35e48c482386a3a97545",
            "b66f3bc64f1ac014f172fef0be7f3d815b8893d2bd5b52991be766abf0175804",
            "bbe83f04bb670efce112a656f753f6545e6baf7700818f6d0ed1c1b37527b1c8",
            "9c604fa5f3154dedb82917258dbff71b3000c906eeef72d20a0178ca615723e4",
            "e0c68866397d57dc4a55221f94f241d5496ce486df7d5db4ba38472326210909",
            "918aec8d13795f30e861a52d10a79f671c6adef750157ed562dc5701c2bd2127",
            "bcdc24644b658a3cce9fdd5c699b665aeff8a9333cadacdc7dda685cb687cfd3",
            "5db5accd62ba27e0d7d9cb0466a0f25b65b79a6d1cdb7a053c048665b77193d0",
            "97630f91ec0e96be975ea300992ef9dc1f066df97e550a4c018228e2071428b4"
        ]),
        domSignatures: [
            {"proxyName":"rammerHead","targetElements":[{"target":".chrome-tabs","content":null},{"target":".browser-tab-content","content":null}]},
            {"proxyName":"rammerHeadv2","targetElements":[{"target":"title","content":"Rammerhead Proxy"},{"target":"h1","content":"Rammerhead Proxy"}]},
            {"proxyName":"interstellar","targetElements":[{"target":".title","content":"Interstellar"},{"target":"input[class='search-home']","content":null}]},
            {"proxyName":"hypertabs","targetElements":[{"target":".chrome-tab-title","content":"New Hypertab"},{"target":".chrome-tabs-content","content":null}]},
            {"proxyName":"hide_my_ass","targetElements":[{"target":".hma-top-logo","content":null},{"target":".hma-logo-link","content":null}]},
            {"proxyName":"taco","targetElements":[{"target":".black_text","content":"Ta‌co Pro‌xy"},{"target":"title","content":"Ta‌co Pr‌oxy"}]},
            {"proxyName":"croxy","targetElements":[{"target":"title[data-trans='yes']","content":"The Most Advanced Secure And Free Web Proxy | CroxyProxy"},{"target":"a[href='https://github.com/croxy-proxy-official/extension']","content":"manually"}]},
            {"proxyName":"electron","targetElements":[{"target":"title","content":"Electron"},{"target":"div#home p","content":"A student's best friend!"}]},
            {"proxyName":"holy_unblocker","targetElements":[{"target":"a[href='https://www.patreon.com/holyunblocker']","content":null},{"target":"a[href='https://github.com/titaniumnetwork-dev/Holy-Unblocker']","content":null}]},
            {"proxyName":"holy_unblockerv2","targetElements":[{"target":"input[class='_thinPadLeft_1s88o_120']","content":null},{"target":"h1","content":"Ending Internet Censorship."}]},
            {"proxyName":"nebula","targetElements":[{"target":"title","content":"Nebula"},{"target":"a[class='stamp']","content":" Nebula © Nebula Services 2022 "},{"target":"input[placeholder='Explore the web freely']","content":null}]},
            {"proxyName":"node_unblocker","targetElements":[{"target":"title","content":"Node Unblocker"},{"target":"a[href='https://github.com/nfriedly/node-unblocker']","content":"available on github"}]},
            {"proxyName":"shuttle","targetElements":[{"target":"title","content":"Shuttle"},{"target":"meta[content='shuttle, the fastest browser']","content":null},{"target":"a[href='https://github.com/shuttlenetwork/shuttle']","content":"Github"}]},
            {"proxyName":"site","targetElements":[{"target":"title","content":"siteproxy代理 - 通向墙外的世界"},{"target":"a[href='https://github.com/netptop/siteproxy']","content":null}]},
            {"proxyName":"ultraviolet","targetElements":[{"target":"title","content":"Genarcy"},{"target":".navbar-logo","content":"Genarcy"}]},
            {"proxyName":"incognito","targetElements":[{"target":"title","content":"Incognito"},{"target":"input[placeholder='Search the web']","content":null}]},
            {"proxyName":"aguse","targetElements":[{"target":"form[name='aguse_form']","content":null},{"target":"img[alt='aguse gateway']","content":null}]},
            {"proxyName":"beaver_unblocker","targetElements":[{"target":"title","content":"Beaver Unblocker"},{"target":".title","content":"Beaver Unblocker"}]},
            {"proxyName":"utopia","targetElements":[{"target":"title","content":"Utopia"},{"target":"meta[content='utopia, math, science, ela, social studies, school, study']","content":null}]},
            {"proxyName":"censor_dodge","targetElements":[{"target":"a[href='http://censordodge.com'][target='blank']","content":"Censor Dodge V1.83 BETA"},{"target":"title","content":"Censor Dodge 1.83 BETA","substringMatch":true}]},
            {"proxyName":"ludicrous","targetElements":[{"target":"h1.Home_main-title__WtTWV span:first-child","content":"Ludicrous"},{"target":"meta[content='Ludicrous | A School Site']","content":null}]},
            {"proxyName":"radar_cloud","targetElements":[{"target":"title","content":"Radar Cloud"},{"target":"meta[content='Radar Cloud']","content":null}]},
            {"proxyName":"surfskip","targetElements":[{"target":"meta[content='SurfSkip is the best web proxy and Web VPN , ensuring private and secure internet browsing. Unlock restricted content, play games, and visit your favorite sites seamlessly with our webproxy  Experience the freedom of SurfSkip, your go-to solution for online privacy.']","content":null},{"target":"title","content":"Surfskip | Free VPN Browser - Your Best Web Proxy"}]},
            {"proxyName":"Art Class","targetElements":[{"target":"a[href='https://github.com/art-class/v4']","content":"GitHub"},{"target":"a[href='https://discord.gg/tMaHQ2dyk5']","content":"Discord"},{"target":"title","content":"Art Class"}]},
            {"proxyName":"dodge_unblocker_v4","targetElements":[{"target":"a[href='https://github.com/dogenetwork/v4']","content":null},{"target":"a[class='title']","content":" Doge Unblocker"}]},
            {"proxyName":"phantom_games","targetElements":[{"target":"meta[content='Phantom Games, the BEST place to find fun unblocked games!'","content":null},{"target":"title","content":"Phantom Games"}]},
            {"proxyName":"tinf­0il","targetElements":[{"target":".heading > h1","content":"Tinf­0il"},{"target":"title","content":"Ti­nf0­il","substringMatch":true}]},
            {"proxyName":"asteroid","targetElements":[{"target":"meta[content='Math explained in easy language, plus puzzles, games, worksheets and an illustrated dictionary. For K-12 kids, teachers and parents.']","content":null},{"target":"title","content":"Inbox"}]},
            {"proxyName":"Equinox_v1","targetElements":[{"target":"input[placeholder='Search the web or enter a URL']","content":null},{"target":"title","content":"Equinox V1"}]},
            {"proxyName":"jordan_math_work","targetElements":[{"target":"meta[name='Jordansmathwork']","content":null},{"target":"title","content":"Jordan's Math Work - V6"}]},
            {"proxyName":"extreme_math","targetElements":[{"target":"meta[content='On ExtremeMath, you can join thousands of people worldwide on the most innovative and exquisite learning platform!']","content":null},{"target":"meta[content='ExtremeMath - The Simplest Form of Education']","content":null}]},
            {"proxyName":"kazwire","targetElements":[{"target":"meta[content='Play and browse for free now on Kazwire!']","content":null},{"target":"title","content":"Kazwire"}]},
            {"proxyName":"interstellar_v2","targetElements":[{"target":"input[placeholder='Search with Google or enter address']","content":null},{"target":".title","content":"Interstellar"},{"target":"title","content":"Home"}]},
            {"proxyName":"polaris","targetElements":[{"target":"meta[content='The professional unblocked gaming site.']","content":null},{"target":"title","content":"Polaris"}]},
            {"proxyName":"outred","targetElements":[{"target":".title","content":"OutRed"},{"target":"title","content":"OutRed","substringMatch":true}]},
            {"proxyName":"math_is_fun","targetElements":[{"target":"meta[content='Math explained in easy language, plus puzzles, games, worksheets and an illustrated dictionary. For K-12 kids, teachers and parents.']","content":null},{"target":"img[alt='Math is Fun']","content":null}]},
            {"proxyName":"doge_unblocker","targetElements":[{"target":"a.title","content":"Doge Unblocker"},{"target":"a[href='https://github.com/dogenetwork/v4']","content":null},{"target":"input[name='url']","content":null}]},
            {"proxyName":"megaingenieria_helpdesk","targetElements":[{"target":"meta[name='keywords']","content":null},{"target":"a[href='https://discord.gointospace.app']","content":null}]},
            {"proxyName":"school_pepikutan","targetElements":[{"target":".chrome-tab-title","content":"New tab"},{"target":".chrome-tab","content":null}]},
            {"proxyName":"test_zecro","targetElements":[{"target":"title","content":"test.zecro.de"},{"target":".chrome-tab","content":null}]},
            {"proxyName":"hp_ilove4ndan","targetElements":[{"target":"title","content":"hp.ilove4ndan.com"},{"target":".chrome-tab","content":null}]},
            {"proxyName":"becrimedo_gay","targetElements":[{"target":"div#particles-js","content":null},{"target":"#subtitle","content":"Entertainment"},{"target":"a[href='/static/calculus/']","content":null}]},
            {"proxyName":"vapor_v3","targetElements":[{"target":"title","content":"VAPOR v3"},{"target":"meta[property='benrogo:uvpath']","content":null}]},
            {"proxyName":"bowldog_proxy","targetElements":[{"target":"title","content":"𐌁ꝊᏔ𐌋𐌃ꝊᏵ 𐌋𐌄𐌀𐌐𐌍𐌉𐌍Ᏽ - Home"},{"target":"img[src='img/bowldog.png']","content":null}]},
            {"proxyName":"velara","targetElements":[{"target":"a[title='Velara - Play Unblocked Games']","content":"VELARA"},{"target":"a[href='https://discord.gg/nowgg']","content":"Join The Discord"}]},
            {"proxyName":"politechnika_nova","targetElements":[{"target":"h1.hero__title","content":"Welcome to Ghost"},{"target":"meta[content='Ghost']","content":null}]},
            {"proxyName":"vaultv6_ajh","targetElements":[{"target":"h1","content":"AJH's Vault V6"},{"target":"p.quote-holder span.quote-thing","content":"Welcome to the student toolbox."},{"target":"input#uv-address","content":null},{"target":"a#cloaker","content":"Launch in about:blank"}]},
            {"proxyName":"unstop_browser","targetElements":[{"target":"noscript","content":"Please enable JavaScript to use this site."},{"target":".chrome-tabs","content":null}]},
            {"proxyName":"rednotsus_portal","targetElements":[{"target":"title","content":"Reds Proxy"},{"target":"#title","content":"Reds Proxy Hub"}]},
            {"proxyName":"utopia_proxy","targetElements":[{"target":"a[href='https://discord.gg/hFZC5cgsmq']","content":null},{"target":"a[href='/gams/']","content":null}]},
            {"proxyName":"reds_exploit_corner","targetElements":[{"target":"a[href='https://github.com/55gms/55gms']","content":null},{"target":"h1#title","content":"Reds Exploit Corner"}]},
            {"proxyName":"Bolt","targetElements":[{"target":"a[href='/lessons']","content":null},{"target":"h1#title","content":"Bolt"}]},
            {"proxyName":"juststudying","targetElements":[{"target":"a[href='https://uk.trustpilot.com/review/juststudy.uk']","content":"Trustpilot"},{"target":"meta[content='The best revision website ever!']","content":null}]},
            {"proxyName":"acceleration","targetElements":[{"target":"input#searchbar","content":null},{"target":"form#searchform","content":null}]},
            {"proxyName":"shadow","targetElements":[{"target":"div#tabs-container","content":null},{"target":"div#bookmarks-container","content":null}]},
            {"proxyName":"mocha","targetElements":[{"target":"title","content":"Mocha"},{"target":"input[placeholder='Enter a search query or URL']","content":null},{"target":"a[href='https://github.com/cafe-labs/mocha']","content":null}]},
            {"proxyName":"Szvy_Central_V2","targetElements":[{"target":"title","content":"calculator - Google Search"},{"target":"meta[content='Szvy Central']","content":null},{"target":"input[placeholder='Search freely with Szvy Central...']","content":null}]},
            {"proxyName":"strongdog","targetElements":[{"target":"title","content":"Str0ngDog XP"},{"target":"a","content":"Random Game"},{"target":"a[href='https://discord.gg/pWjfQ4Sz5c']","content":"Discord server"}]},
            {"proxyName":"unblockee_games","targetElements":[{"target":"a[aria-label='Browse movies']","content":"Movies"},{"target":"h1","content":"Unblockee games"},{"target":"a[aria-label='Access proxy']","content":"Proxy"},{"target":"button","content":"Changelog"}]},
            {"proxyName":"utopia_v2","targetElements":[{"target":"title","content":"Utopia Education"},{"target":"meta[content='An educational website full of school topics and academic resources. The perfect place for students to learn']","content":null},{"target":"input[placeholder='Dive into the web']","content":null}]},
            {"proxyName":"unblokee_games","targetElements":[{"target":"h1#page-header","content":"Unblockee games"},{"target":"button#toggle-view","content":"Toggle Websites"}]},
            {"proxyName":"strong_dog","targetElements":[{"target":"div#favoritesOverlay","content":null},{"target":"div#allGameList","content":null}]},
            {"proxyName":"shuttle","targetElements":[{"target":"iframe#ifr","content":null},{"target":"a[href='https://github.com/shuttlenetwork/shuttle']","content":"Github"}]},
            {"proxyName":"truffled","targetElements":[{"target":"div#particles-js","content":null},{"target":"script[src='battery.js']","content":null}]},
            {"proxyName":"boredom_v2","targetElements":[{"target":"input#uv-address","content":null},{"target":"form#uv-form h1","content":"Boredom v2"}]},
            {"proxyName":"frogie","targetElements":[{"target":"div#particles-js","content":null},{"target":"script[src='/particles.js']","content":null}]},
            {"proxyName":"verycool","targetElements":[{"target":"#uv-search-engine","content":null},{"target":"a[href='https://github.com/TheTIW/UV-Static']","content":null}]},
            {"proxyName":"DextensifyProxy","targetElements":[{"target":"title","content":"Dextensify","substringMatch":false},{"target":"h1","content":"Dextensify","substringMatch":false},{"target":"#buttons_container p","content":"Detecting extensions...","substringMatch":true},{"target":"script","content":"chrome-extension://","substringMatch":true}]},
            {"proxyName":"ExtHang3rProxy","targetElements":[{"target":"title","content":"ExtHang3r","substringMatch":false},{"target":"button#hangButton","content":"Hang Extension!","substringMatch":false},{"target":"select#iframeSelect","content":null,"substringMatch":false}]},
            {"proxyName":"johnson_education","targetElements":[{"target":"h1#maintitle","content":"Johnson Education"},{"target":"input#teacher-lookup","content":null}]},
            {"proxyName":"hype_study","targetElements":[{"target":"meta[content='Secure, animated, and modern study platform designed for serious learners. Create flashcards, take quizzes, track your progress with advanced analytics, and master any subject with confidence.']","content":null},{"target":"meta[content='HypeStudy — Secure Study Platform for Students']","content":null}]},
            {"proxyName":"ubghub","targetElements":[{"target":"a[href='/']","content":"UBGHub"},{"target":"meta[content='unblocked games, unblocked sites, game directory, unblocked content, school games, proxy games']","content":null}]},
            {"proxyName":"dogeub","targetElements":[{"target":"title","content":"v5-static","substringMatch":true},{"target":"input[placeholder='Search Google or type URL']","content":null}]},
            {"proxyName":"daybits_study","targetElements":[{"target":"title#window_title","content":"Study.com"},{"target":"div[data-url='zones']","content":null}]},
            {"proxyName":"ccported","targetElements":[{"target":"title","content":"CCPorted"},{"target":"a[href='/tab-cloaker']","content":null}]},
            {"proxyName":"strawberry_proxy","targetElements":[{"target":"title","content":"Strawberry"},{"target":"span#lunar-scheme","content":"strawberry://"},{"target":"iframe#proxy-frame","content":null}]},
            {"proxyName":"vapor_v4","targetElements":[{"target":"iframe#content-frame","content":null},{"target":"button#tab-cloak-btn","content":null},{"target":"button#show-whats-new-btn","content":null},{"target":"meta[content='IXL Learning']","content":null}]},
            {"proxyName":"vaporized_educational","targetElements":[{"target":"title","content":"Educational - Empowering Academic Excellence Through Interactive Learning"},{"target":"div.quiz-section","content":null}]},
            {"proxyName":"daydreamX","targetElements":[{"target":"meta[content='Your favorite Browser in a browser']","content":null},{"target":"meta[content='Daydream, Daydream Browser, Daydream Browser, Daydream Browser, Daydream Security Browser']","content":null}]},
            {"proxyName":"void_netwpork_v5","targetElements":[{"target":".holographic-title","content":"Void Network V5"},{"target":"input[placeholder='Search for Games/Apps...'", "content":null}]},
            {"proxyName":"velara","targetElements":[{"target":"h1","content":"Welcome to Velara"},{"target":"input[placeholder='Search the web freely'", "content":null}]},
            {"proxyName":"frogies_arcade_v4","targetElements":[{"target":".maintitle","content":"frogie's arcade v4"},{"target":"input[placeholder='search anything...'", "content":null}]}
        ]
    };

    // core engine implementation
    class ByProxieEngine {
        constructor() {
            this.config = {
                enabled: false,
                confidenceThreshold: 70,
                eventId: 'BYPROXIE_DETECTED',
                hooks: { fetch: true, xhr: true, ws: true, sw: true, wasm: true, history: true, response: true },
                onDetect: null // optional callback function
            };
            this.rules = { ...DEFAULT_RULES };
            this.scannedScripts = new WeakSet();
            this.hashedUrls = new Set();
            this.observer = null;
            this.loopActive = false;
        }

        /**
         * initializes and starts the engine with merged configuration
         * @param {object} options configuration object
         */
        init(options = {}) {
            if (this.config.enabled) return;

            this.config = { ...this.config, ...options, hooks: { ...this.config.hooks, ...(options.hooks || {}) } };
            
            if (options.customRules) {
                if (options.customRules.urlPatterns) this.rules.urlPatterns.push(...options.customRules.urlPatterns);
                if (options.customRules.keywords) this.rules.keywords.push(...options.customRules.keywords);
                if (options.customRules.hashes) options.customRules.hashes.forEach(h => this.rules.hashes.add(h));
                if (options.customRules.domSignatures) this.rules.domSignatures.push(...options.customRules.domSignatures);
            }

            this.config.enabled = true;
            this.loopActive = true;
            
            this._applyHooks();
            this._startScanners();
            this._startContinuousLoop();

            global.addEventListener('beforeunload', () => { this.loopActive = false; });
        }

        _trigger(threat, context, confidence = 100) {
            if (!this.config.enabled || confidence < this.config.confidenceThreshold) return;

            const payload = { threat, context, confidence, timestamp: Date.now() };

            try {
                // dispatch dom event for isolated world listeners
                const evt = new NATIVE.CustomEvent(this.config.eventId, { detail: payload });
                NATIVE.dispatchEvent(evt);
            } catch (e) {}

            if (typeof this.config.onDetect === 'function') {
                // fire direct callback if configured
                this.config.onDetect(payload);
            }
        }

        // scanners and analyzers
        _isProxyUrl(url) {
            let cleanStr = String(url);
            try { cleanStr = new URL(cleanStr, global.location.origin).pathname; } catch {}
            return this.rules.urlPatterns.some(r => r.test(cleanStr));
        }

        _scanTextForKeywords(text, sourceInfo) {
            if (!text || typeof text !== 'string') return;
            const lower = text.toLowerCase();
            for (const kw of this.rules.keywords) {
                if (lower.includes(kw.toLowerCase())) {
                    this._trigger('Source Code Keyword Match', `Found '${kw}' in ${sourceInfo.substring(0, 50)}`, 100);
                    break;
                }
            }
        }

        async _hashAndVerifyAsset(url) {
            if (!url || typeof url !== 'string' || this.hashedUrls.has(url)) return;
            try {
                const u = new URL(url, global.location.origin);
                if (u.origin !== global.location.origin) return; // enforce same-origin to avoid cors errors

                this.hashedUrls.add(url);
                const response = await NATIVE.fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit' });
                if (!response.ok) return;

                const buffer = await response.arrayBuffer();
                const hashBuffer = await NATIVE.crypto.subtle.digest('SHA-256', buffer);
                const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

                if (this.rules.hashes.has(hashHex)) {
                    this._trigger('Malicious Asset Hash Match', `Asset signature matched: ${u.pathname}`, 100);
                }
            } catch (e) {} // silently ignore fetch errors
        }

        _scanExternalScripts() {
            try {
                const scripts = global.document.querySelectorAll('script[src]');
                for (let i = 0; i < scripts.length; i++) {
                    const script = scripts[i];
                    if (this.scannedScripts.has(script)) continue;
                    this.scannedScripts.add(script);
                    
                    const src = script.src;
                    if (src && src.startsWith(global.location.origin)) {
                        NATIVE.fetch(src)
                            .then(res => res.text())
                            .then(text => this._scanTextForKeywords(text, src))
                            .catch(() => {});
                    }
                }
            } catch(e) {}
        }

        _scanDOMFeatures() {
            try {
                // check for known proxy container elements
                if (global.document.querySelector('.scram-frame, .scramjet-container, #uv-iframe, #scramjet-frame')) {
                    this._trigger('Proxy DOM Element', 'Container found', 100);
                }

                // scan inline scripts for proxy rewrite signatures
                const scripts = global.document.getElementsByTagName('script');
                for (let i = 0; i < scripts.length; i++) {
                    const c = scripts[i].textContent || '';
                    if (c.length > 0) {
                        this._scanTextForKeywords(c, 'Inline Script block');
                        if (/rewriteHTML\s*\(|rewriteCSS\s*\(|rewriteJS\s*\(|unproxyUrl\s*\(|__uv\$encode|ScramjetController\s*\(/.test(c)) {
                            this._trigger('Proxy Rewrite Engine', 'Inline script regex match', 99);
                        }
                    }
                }

                // evaluate advanced dom fingerprint signatures
                for (const proxy of this.rules.domSignatures) {
                    let allConditionsMet = true;
                    for (const targetObj of proxy.targetElements) {
                        const elements = global.document.querySelectorAll(targetObj.target);
                        if (elements.length === 0) { allConditionsMet = false; break; }

                        if (targetObj.content !== null) {
                            let matchedContent = Array.from(elements).some(el => {
                                const text = el.textContent || el.getAttribute('content') || el.value || el.src || '';
                                return targetObj.substringMatch === false ? text.trim() === targetObj.content : text.includes(targetObj.content);
                            });
                            if (!matchedContent) { allConditionsMet = false; break; }
                        }
                    }
                    if (allConditionsMet) {
                        this._trigger('DOM Fingerprint Signature', `Matched Proxy Config: ${proxy.proxyName}`, 100);
                        break;
                    }
                }
            } catch (e) {}
        }

        _startScanners() {
            // perform initial scan on load
            this._scanDOMFeatures();
            this._scanExternalScripts();
            global.document.querySelectorAll('img[src], script[src], link[href]').forEach(el => this._hashAndVerifyAsset(el.src || el.href));

            // observe dom mutations to catch dynamically injected assets
            this.observer = new NATIVE.MutationObserver((mutations) => {
                for (const m of mutations) {
                    for (const node of m.addedNodes) {
                        if (node.nodeType !== 1) continue;
                        const tag = node.tagName?.toUpperCase();

                        if (tag === 'SCRIPT') {
                            if (this._isProxyUrl(node.src)) this._trigger('Dynamic Script Inject', node.src, 97);
                            else this._scanTextForKeywords(node.textContent || '', 'Dynamic Inline Script');
                            this._hashAndVerifyAsset(node.src);
                        } else if (tag === 'IFRAME') {
                            if (node.id === 'uv-iframe' || node.id === 'scramjet-frame') this._trigger('Proxy Iframe Element', node.id, 100);
                            if (this._isProxyUrl(node.src)) this._trigger('Proxy Iframe Src', node.src, 97);
                        } else if (tag === 'IMG' || tag === 'LINK') {
                            this._hashAndVerifyAsset(node.src || node.href);
                        }
                    }
                }
                this._scanDOMFeatures(); // re-evaluate fingerprints on dom changes
            });

            this.observer.observe(global.document.documentElement, { childList: true, subtree: true });
        }

        _startContinuousLoop() {
            // run continuous scans on randomized intervals to catch delayed injections
            const runLoop = () => {
                if (!this.loopActive || !this.config.enabled) return;
                
                this._scanDOMFeatures();
                this._scanExternalScripts();
                
                // randomize interval to mitigate predictable evasion
                NATIVE.setTimeout(runLoop, 350 + Math.floor(Math.random() * 350));
            };
            
            NATIVE.setTimeout(runLoop, 300);
        }

        // native api hooks
        _applyHooks() {
            const self = this;

            if (this.config.hooks.fetch) {
                global.fetch = function(...args) {
                    const url = String(args[0]?.url || args[0] || '');
                    if (self._isProxyUrl(url)) self._trigger('Fetch Intercept', url, 95);
                    return NATIVE.fetch.apply(this, args);
                };
            }

            if (this.config.hooks.xhr) {
                global.XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                    const s = String(url || '');
                    if (self._isProxyUrl(s)) self._trigger('XHR Intercept', s, 95);
                    return NATIVE.XHROpen.call(this, method, url, ...rest);
                };
            }

            if (this.config.hooks.ws) {
                global.WebSocket = function(url, protocols) {
                    const s = String(url || '');
                    if (/wss?:\/\/[^/]+\/wisp\/?/.test(s)) self._trigger('Wisp WebSocket', s, 100);
                    else if (/wss?:\/\/[^/]+\/bare\/v[0-9]+\//.test(s)) self._trigger('Bare-Server WebSocket', s, 100);
                    else if (/wss?:\/\/[^/]+\/ws\//.test(s) && self._isProxyUrl(s)) self._trigger('Proxy WebSocket', s, 80);
                    return new NATIVE.WebSocket(url, protocols);
                };
                global.WebSocket.prototype = NATIVE.WebSocket.prototype;
            }

            if (this.config.hooks.wasm && global.WebAssembly && NATIVE.WasmInstantiate) {
                global.WebAssembly.instantiate = async function(source, ...rest) {
                    if (source instanceof Response && /scramjet|scram.*codec|epoxy/i.test(source.url || '')) {
                        self._trigger('WASM Instantiate (Scramjet)', source.url, 92);
                    }
                    return NATIVE.WasmInstantiate.call(global.WebAssembly, source, ...rest);
                };
            }

            if (this.config.hooks.sw && global.navigator.serviceWorker && NATIVE.SWRegister) {
                global.navigator.serviceWorker.register = function(scriptUrl, options) {
                    const url = String(scriptUrl || '').toLowerCase();
                    if (/\/uv\.sw\.js|\/corro\.sw\.js|\/scramjet\/(worker|sw)|\/baremux\/worker|\/epoxy\/worker|\/wisp[-_]?worker/.test(url)) {
                        self._trigger('Service Worker Registration', url, 98);
                    }
                    return NATIVE.SWRegister.call(global.navigator.serviceWorker, scriptUrl, options);
                };
            }

            if (this.config.hooks.history) {
                if (global.history && NATIVE.historyPushState) {
                    global.history.pushState = function(state, unused, url) {
                        if (url && self._isProxyUrl(url)) self._trigger('History API Pivot (Push)', url, 90);
                        return NATIVE.historyPushState.call(this, state, unused, url);
                    };
                }
                if (global.history && NATIVE.historyReplaceState) {
                    global.history.replaceState = function(state, unused, url) {
                        if (url && self._isProxyUrl(url)) self._trigger('History API Pivot (Replace)', url, 90);
                        return NATIVE.historyReplaceState.call(this, state, unused, url);
                    };
                }
            }

            if (this.config.hooks.response && global.Response && NATIVE.ResponseText) {
                global.Response.prototype.text = function() {
                    return NATIVE.ResponseText.call(this).then(text => {
                        try { self._scanTextForKeywords(text, this.url || 'Dynamic fetch response'); } catch(e) {}
                        return text;
                    });
                };
            }
        }
    }

    // expose library to the global scope
    global.ByProxie = new ByProxieEngine();

})(window);
