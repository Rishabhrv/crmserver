import React from 'react'
import Slidebar from '../components/Slidebar'
import HomePageMsg from '../components/HomePageMsg'
import ChatPagechats from '../components/ChatPagechats'

const SingleUserChat = () => {
  return (
    <div className='flex'>
        <Slidebar />
          <ChatPagechats />
          <HomePageMsg />
    </div>
  )
}

export default SingleUserChat