package org.tsicoop.sign.framework;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * One Action per resource path in _processor.tsi (TSI framework standard —
 * matches tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault). InterceptingFilter
 * resolves auth and the target Action before calling validate() then post();
 * the specific operation is the "_func" field in the JSON body, dispatched
 * inside post() — never a URL path parameter.
 */
public interface Action {

    void post(HttpServletRequest req, HttpServletResponse res);

    boolean validate(String method, HttpServletRequest req, HttpServletResponse res);
}
