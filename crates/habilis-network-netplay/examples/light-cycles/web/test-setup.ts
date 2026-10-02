import { GlobalRegistrator } from '@happy-dom/global-registrator'

GlobalRegistrator.register()

/**
 * happy-dom starts on `about:blank`, where `pushState` and `replaceState` are
 * rejected because there is no origin to be same-origin with. Nothing here
 * vendors `visage-router`, but keeping this identical to the agent-share
 * precedent this file was copied from costs nothing and avoids drift.
 */
declare const happyDOM: { setURL(url: string): void }
happyDOM.setURL('http://localhost/')
