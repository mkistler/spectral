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

// Check that security is an array of valid security requirement objects
function checkSecurity(security: unknown, path: string[], schemes: object): IFunctionResult[] {
  if (!Array.isArray(security)) {
    return [];
  }

  const schemeNames = Object.keys(schemes);

  const results: IFunctionResult[] = [];

  for (const [index, item] of security.entries()) {
    if (!isObject(item)) {
      continue; // will be flagged by oas[23]-schema
    }

    const securityKeys = Object.keys(item);

    for (const securityKey of securityKeys) {
      if (!schemeNames.includes(securityKey)) {
        continue; // will be flagged by oas[23]-operation-security-defined
      }
      const scheme: unknown = schemes[securityKey];
      if (!isObject(scheme)) {
        continue; // will be flagged by oas[23]-schema
      }
      const { type } = scheme;
      if (typeof type !== 'string') {
        continue; // will be flagged by oas[23]-schema
      }
      const securityValue = item[securityKey];
      if (!Array.isArray(securityValue)) {
        continue; // will be flagged by oas[23]-schema
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
                path: [...path, index, securityKey],
              });
            }
          }
        } else {
          continue; // will be flagged by oas[23]-schema
        }
      } else {
        if (securityValue.length !== 0) {
          results.push({
            message: `Scopes array must be empty for security scheme of type "${type}".`,
            path: [...path, index, securityKey],
          });
        }
      }
    }
  }

  return results;
}

export default createRulesetFunction<{ paths: Record<string, unknown>; security: Record<string, unknown>[] }, null>(
  {
    input: {
      type: 'object',
      properties: {
        paths: {
          type: 'object',
        },
        security: {
          type: 'array',
          items: {
            type: 'object',
          },
        },
      },
    },
    options: null,
  },
  function oasSecurityRequirement(targetVal, opts, context) {
    const isOAS3X = context.document.formats?.has(oas3) === true;

    const schemesPath = isOAS3X ? ['components', 'security'] : ['securityDefinitions'];
    const schemes: unknown = _get(targetVal, schemesPath);

    if (!isObject(schemes)) {
      return []; // will be flagged by oas[23]-operation-security-defined
    }

    const results: IFunctionResult[] = [];

    const { security } = targetVal;

    results.push(...checkSecurity(security, ['security'], schemes));

    const { paths } = targetVal;
    for (const { path, operation: method, value: operation } of getAllOperations(paths)) {
      if (!isObject(operation)) continue;

      const { security } = operation;

      results.push(...checkSecurity(security, ['paths', path, method, 'security'], schemes));
    }

    return results;
  },
);
