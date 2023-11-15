<script>
  const transport = new WebTransport('https://localhost:4000')
  transport.ready.then(console.log)
  transport.closed.then(console.log)
</script>