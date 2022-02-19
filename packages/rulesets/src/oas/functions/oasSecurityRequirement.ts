import type { JsonPath } from '@stoplight/types';
import { createRulesetFunction, IFunctionResult } from '@stoplight/spectral-core';
import { oas3 } from '@stoplight/spectral-formats';

import { getAllOperations } from './utils/getAllOperations';
import { isObject } from './utils/isObject';

function _get(value: unknown, path: JsonPath): unknown {
  for (const segment of path) {
    if (!isObject(value)) {
      break;
    }

    value = value[segment];
  }

  return value;
}

export default createRulesetFunction<{ paths: Record<string, unknown> }, null>(
  {
    input: {
      type: 'object',
      properties: {
        paths: {
          type: 'object',
        },
      },
    },
    options: null,
  },
  function oasSecurityRequirement(targetVal, opts, context) {
    const { paths } = targetVal;

    const results: IFunctionResult[] = [];

    const isOAS3X = context.document.formats?.has(oas3) === true;

    const schemesPath = isOAS3X ? ['components', 'security'] : ['securityDefinitions'];
    const schemes: unknown = _get(targetVal, schemesPath);

    if (!isObject(schemes)) {
      // No message here -- it will be flagged by oas[23]-operation-security-defined
      return results;
    }
    const schemeNames = Object.keys(schemes);

    for (const { path, operation: method, value: operation } of getAllOperations(paths)) {
      if (!isObject(operation)) continue;

      const { security } = operation;

      if (!Array.isArray(security)) {
        continue;
      }

      for (const [index, value] of security.entries()) {
        if (!isObject(value)) {
          continue;
        }

        const securityKeys = Object.keys(value);

        for (const securityKey of securityKeys) {
          if (!schemeNames.includes(securityKey)) {
            // No message here -- it will be flagged by oas[23]-operation-security-defined
            continue;
          }
          const scheme: unknown = schemes[securityKey];
          if (!isObject(scheme)) {
            // No message here -- it will be flagged by oas[23]-schema
            continue;
          }
          const { type } = scheme;
          if (typeof type !== 'string') {
            // No message here -- it will be flagged by oas[23]-schema
            continue;
          }
          const securityValue = value[securityKey];
          if (!Array.isArray(securityValue)) {
            // No message here -- it will be flagged by oas[23]-schema
            continue;
          }

          if (type === 'oauth2' || type === 'openIdConnect') {
            const { scopes } = scheme;
            if (isObject(scopes)) {
              // entries are scopes of security scheme
              const scopeNames = Object.keys(scopes);
              for (const value of securityValue) {
                if (!scopeNames.includes(value)) {
                  results.push({
                    message: `Scope for security "${value}" is not defined for security scheme "${securityKey}".`,
                    path: ['paths', path, method, 'security', index, securityKey],
                  });
                }
              }
            } else {
              // No message here -- it will be flagged by oas[23]-schema
              continue;
            }
          } else {
            if (securityValue.length !== 0) {
              results.push({
                message: `Scopes array must be empty for security scheme of type "${type}".`,
                path: ['paths', path, method, 'security', index, securityKey],
              });
            }
          }
        }
      }
    }

    return results;
  },
);
