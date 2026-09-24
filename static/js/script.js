(function(){
  const container=document.getElementById('three-bg');
  if(!container||typeof THREE==='undefined') return;
  const scene=new THREE.Scene(), camera=new THREE.PerspectiveCamera(65,innerWidth/innerHeight,.1,1000);
  const renderer=new THREE.WebGLRenderer({alpha:true,antialias:true}); renderer.setPixelRatio(Math.min(devicePixelRatio,2)); renderer.setSize(innerWidth,innerHeight); container.appendChild(renderer.domElement); camera.position.z=7;
  const group=new THREE.Group(); scene.add(group);
  const geo=new THREE.BufferGeometry(), count=900, pos=new Float32Array(count*3);
  for(let i=0;i<count;i++){pos[i*3]=(Math.random()-.5)*18;pos[i*3+1]=(Math.random()-.5)*11;pos[i*3+2]=(Math.random()-.5)*10;}
  geo.setAttribute('position',new THREE.BufferAttribute(pos,3)); const mat=new THREE.PointsMaterial({color:0x72e6ff,size:.025,transparent:true,opacity:.8}); group.add(new THREE.Points(geo,mat));
  const torus=new THREE.Mesh(new THREE.TorusKnotGeometry(1.35,.035,120,16),new THREE.MeshBasicMaterial({color:0x6d5dfc,wireframe:true,transparent:true,opacity:.35})); torus.position.set(3,1,-2); group.add(torus);
  const ring=new THREE.Mesh(new THREE.TorusGeometry(2.1,.018,16,100),new THREE.MeshBasicMaterial({color:0x22d3ee,transparent:true,opacity:.25})); ring.rotation.x=1.1; ring.position.set(-3,-1,-3); group.add(ring);
  addEventListener('resize',()=>{camera.aspect=innerWidth/innerHeight;camera.updateProjectionMatrix();renderer.setSize(innerWidth,innerHeight)});
  addEventListener('pointermove',e=>{group.rotation.y=(e.clientX/innerWidth-.5)*.18;group.rotation.x=(e.clientY/innerHeight-.5)*-.1});
  function animate(){requestAnimationFrame(animate);torus.rotation.x+=.002;torus.rotation.y+=.004;ring.rotation.z+=.002;renderer.render(scene,camera)}animate();
})();
