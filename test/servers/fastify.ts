import { expect } from 'chai';
import 'mocha';
import type { FastifyInstance } from 'fastify';
import nacl from 'tweetnacl';
import { SlashCreator, FastifyServer } from '../../src';

describe('FastifyServer', () => {
  const keys = nacl.sign.keyPair();
  let server: FastifyServer;
  let app: FastifyInstance;

  /** @param payload The exact request body to sign. */
  function signedHeaders(payload: string): Record<string, string> {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    return {
      'content-type': 'application/json',
      'x-signature-timestamp': timestamp,
      'x-signature-ed25519': Buffer.from(nacl.sign.detached(Buffer.from(timestamp + payload), keys.secretKey)).toString(
        'hex'
      )
    };
  }

  function attachCreator(): SlashCreator {
    return new SlashCreator({
      applicationID: '1',
      publicKey: Buffer.from(keys.publicKey).toString('hex')
    }).withServer(server);
  }

  beforeEach(() => {
    server = new FastifyServer();
    app = server.app;
  });

  afterEach(async () => {
    await app.close();
  });

  it('starts listening with Fastify listen options', async () => {
    attachCreator();
    await server.listen(0, '127.0.0.1');

    expect(app.server.listening).to.equal(true);
  });

  it('accepts an existing Fastify instance', async () => {
    server = new FastifyServer(app, { alreadyListening: true });
    attachCreator();
    const payload = '{"type":1}';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });

    expect(server.app).to.equal(app);
    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ type: 1 });
    await server.listen();
    expect(app.server.listening).to.equal(false);
  });

  it('accepts Fastify options and preserves their body limit', async () => {
    await app.close();
    server = new FastifyServer({ bodyLimit: 8 });
    app = server.app;
    attachCreator();
    const payload = '{"type":1}';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });

    expect(response.statusCode).to.equal(413);
  });

  it('verifies the original JSON including whitespace and Unicode', async () => {
    attachCreator();
    const payload = '{\n  "type": 1, "text": "Hello 🌍"\n}';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });

    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ type: 1 });
  });

  it('rejects a body changed after signing', async () => {
    attachCreator();
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders('{"type":1,"original":true}'),
      payload: '{"type":1}'
    });

    expect(response.statusCode).to.equal(401);
    expect(response.body).to.equal('Invalid signature');
  });

  it('rejects requests without signature headers', async () => {
    attachCreator();
    const response = await app.inject({ method: 'POST', url: '/interactions', payload: { type: 1 } });

    expect(response.statusCode).to.equal(401);
  });

  it('rejects malformed JSON', async () => {
    attachCreator();
    const payload = '{';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });

    expect(response.statusCode).to.equal(400);
  });

  it('keeps its JSON parser scoped to the interaction routes', async () => {
    app.post('/other', async (request) => ({ body: request.body, hasRawBody: 'rawBody' in request }));
    attachCreator();
    const response = await app.inject({ method: 'POST', url: '/other', payload: { untouched: true } });

    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ body: { untouched: true }, hasRawBody: false });
  });

  it('supports an existing custom JSON parser without changing unrelated routes', async () => {
    app.addContentTypeParser('application/json', { parseAs: 'string' }, (_request, _payload, done) => {
      done(null, { customParser: true });
    });
    app.post('/other', async (request) => request.body);
    attachCreator();
    const payload = '{"type":1}';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });
    const otherResponse = await app.inject({ method: 'POST', url: '/other', payload: { type: 1 } });

    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ type: 1 });
    expect(otherResponse.json()).to.deep.equal({ customParser: true });
  });

  it('preserves raw JSON before the parser removes prototype properties', async () => {
    attachCreator();
    const payload = '{"type":1,"__proto__":{"polluted":true},"constructor":{"prototype":{}}}';
    const response = await app.inject({
      method: 'POST',
      url: '/interactions',
      headers: signedHeaders(payload),
      payload
    });

    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ type: 1 });
    expect({}).not.to.have.property('polluted');
  });

  it('waits for an asynchronous interaction response', async () => {
    server.createEndpoint('/interactions', async (_request, respond) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      await respond({ status: 202, headers: { 'x-test': 'delayed' }, body: { delayed: true } });
    });
    const response = await app.inject({ method: 'POST', url: '/interactions', payload: { type: 1 } });

    expect(response.statusCode).to.equal(202);
    expect(response.headers['x-test']).to.equal('delayed');
    expect(response.json()).to.deep.equal({ delayed: true });
  });

  it('allows a response after the interaction handler has returned', async () => {
    const creator = new SlashCreator({
      applicationID: '1',
      publicKey: Buffer.from(keys.publicKey).toString('hex'),
      handleCommandsManually: true,
      endpointPath: '/manual'
    }).withServer(server);
    creator.on('commandInteraction', (_interaction, respond) => {
      setTimeout(() => void respond({ body: { type: 5 } }), 10);
    });
    const payload = '{"type":2}';
    const response = await app.inject({ method: 'POST', url: '/manual', headers: signedHeaders(payload), payload });

    expect(response.statusCode).to.equal(200);
    expect(response.json()).to.deep.equal({ type: 5 });
  });

  it('sends an empty acknowledgement without a response body', async () => {
    server.createEndpoint('/interactions', async (_request, respond) => {
      await respond({ status: 202 });
    });
    const response = await app.inject({ method: 'POST', url: '/interactions', payload: { type: 1 } });

    expect(response.statusCode).to.equal(202);
    expect(response.body).to.equal('');
  });

  it('sends files and the interaction payload as multipart data', async () => {
    server.createEndpoint('/interactions', async (_request, respond) => {
      await respond({
        body: { type: 4, data: { content: 'Attachment' } },
        files: [{ name: 'hello.txt', file: Buffer.from('Hello world') }]
      });
    });
    const response = await app.inject({ method: 'POST', url: '/interactions', payload: { type: 1 } });

    expect(response.statusCode).to.equal(200);
    expect(response.headers['content-type']).to.include('multipart/form-data; boundary=');
    expect(response.body).to.include('name="files[0]"; filename="hello.txt"');
    expect(response.body).to.include('Hello world');
    expect(response.body).to.include('name="payload_json"');
    expect(response.body).to.include('{"type":4,"data":{"content":"Attachment"}}');
  });
});
