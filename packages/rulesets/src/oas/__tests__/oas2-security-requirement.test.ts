import { DiagnosticSeverity } from '@stoplight/types';
import testRule from './__helpers__/tester';

testRule('oas2-security-requirement', [
  {
    name: 'correct security requirements -- operation level',
    document: {
      swagger: '2.0',
      securityDefinitions: {
        oauth: {
          type: 'oauth2',
          authorizationUrl: 'http://swagger.io/api/oauth/dialog',
          flow: 'implicit',
          scopes: {
            'write:pets': 'modify pets in your account',
            'read:pets': 'read your pets',
          },
        },
        apikey: {
          type: 'apiKey',
          name: 'api_key',
          in: 'header',
        },
        basic: {
          type: 'basic',
        },
      },
      paths: {
        '/pets': {
          get: {
            security: [
              {
                oauth: ['read:pets'],
              },
            ],
          },
          post: {
            security: [
              {
                oauth2: ['write:pets'],
              },
            ],
          },
        },
        '/widgets': {
          get: {
            security: [
              {
                apikey: [],
              },
            ],
          },
        },
        '/health': {
          get: {
            security: [
              {
                basic: [],
              },
            ],
          },
        },
      },
    },
    errors: [],
  },

  {
    name: 'correct security requirements -- API level',
    document: {
      swagger: '2.0',
      securityDefinitions: {
        oauth: {
          type: 'oauth2',
          authorizationUrl: 'http://swagger.io/api/oauth/dialog',
          flow: 'implicit',
          scopes: {
            'read:pets': 'read pets in your account',
          },
        },
        apikey: {
          type: 'apiKey',
          name: 'api_key',
          in: 'header',
        },
        basic: {
          type: 'basic',
        },
      },
      security: [
        {
          oauth: ['read:pets'],
        },
        {
          apikey: [],
        },
        {
          basic: [],
        },
      ],
      paths: {
        '/Pets': {
          get: {},
        },
      },
    },
    errors: [],
  },

  {
    name: 'invalid basic security requirement - operation level',
    document: {
      swagger: '2.0',
      securityDefinitions: {
        basic: {
          type: 'basic',
        },
      },
      paths: {
        '/pets': {
          get: {
            security: [
              {
                basic: ['http'],
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message: `Scopes array must be empty for security scheme of type "basic".`,
        path: ['paths', '/pets', 'get', 'security', '0', 'basic'],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: 'invalid apikey security requirement - operation level',
    document: {
      swagger: '2.0',
      securityDefinitions: {
        apikey: {
          type: 'apiKey',
          name: 'api_key',
          in: 'header',
        },
      },
      paths: {
        '/pets': {
          get: {
            security: [
              {
                apikey: ['secret'],
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message: `Scopes array must be empty for security scheme of type "apiKey".`,
        path: ['paths', '/pets', 'get', 'security', '0', 'apikey'],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },

  {
    name: 'invalid oauth2 security requirement - operation level',
    document: {
      swagger: '2.0',
      securityDefinitions: {
        oauth: {
          type: 'oauth2',
          authorizationUrl: 'http://swagger.io/api/oauth/dialog',
          flow: 'implicit',
          scopes: {
            'write:pets': 'modify pets in your account',
            'read:pets': 'read your pets',
          },
        },
      },
      paths: {
        '/pets': {
          get: {
            security: [
              {
                oauth: ['get:pets'],
              },
            ],
          },
        },
      },
    },
    errors: [
      {
        message: `Scope for security "get:pets" is not defined for security scheme "oauth".`,
        path: ['paths', '/pets', 'get', 'security', '0', 'oauth'],
        severity: DiagnosticSeverity.Warning,
      },
    ],
  },
]);
