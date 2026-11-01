export function isEphemeralDist(directory) {
  return /(?:^|[/\\])\.next-(?:browser|safety)-[^/\\]+/.test(directory);
}

export function stableDeclarations(snapshot, typesDirectory) {
  return snapshot.replace(
    /(["'])\.\/(?:[^/"'\s]+\/)*\.next-(?:browser|safety)-[^/"'\s]+\/(?:dev\/)?types\//g,
    (_match, quote) => quote + './' + typesDirectory + '/',
  );
}
