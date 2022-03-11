

let -g ADD_ME=0
function a()
{
  let -g ADD_ME
  ADD_ME=1
}
echo "ADD_ME: $ADD_ME"
